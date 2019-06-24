class CodeRegion:
    """A class that describes a given code region of a given code type.

    Attributes
    ----------
        start (int): start address (ea) of the code region
        end (int): end address (ea) of the code region
        code_type (int): code type of the code region
        changed (bool): True iff the code region was changed after construction
        prev (CodeRegion): the previous code region (memory order), None if first
        next (CodeRegion): the next code region (memory order), None if last

    Notes
    -----
        1. Code regions only live during a single thumb's up scan, during all of it's iterations
        2. Code regions will be changed if merged together with other regions / got resized
    """

    def __init__(self, start, end, code_type):
        """Create a code region instance.

        Args:
            start (int): effective address of the region's start
            end (int): effective address of the region's end
            code_type (int): cpu code type
        """
        self.start = start
        self.end = end
        self.code_type = code_type
        self.changed = False
        self.prev = None
        self.next = None

    def link(self, region):
        """Link the given region after ourselves.

        Args:
            region (CodeRegion): code region that should be linked after us
        """
        region.prev = self
        if self.next is not None:
            self.next.prev = region
        if region.next is None:
            region.next = self.next
        self.next = region

    def resizeStart(self, new_start):
        """Resize the region, and modify it's start.

        Args:
            new_start (int): new effective address for the region's start
        """
        if self.prev is not None:
            self.prev.end = new_start
            # no need to mark it as changed
        self.start = new_start
        self.changed = True

class CodeRegions:
    """A class that describes the overall set of seen code regions during a thumb's up scan.

    Attributes
    ----------
        _regions (list): list of seen code region, sorted by their order in memory

    Notes
    -----
        1. Code regions are stored sorted by their in-memory order (by address)
        2. During the first iteration the list is being populated
        3. Code regions are only allowed to be inserted by the sorting order
        4. After the first iteration, regions are only merged / resized - we do not support new insertions
    """

    def __init__(self):
        """Create the instance for managing the code regions of the current scan."""
        self._regions = []

    def insert(self, region):
        """Insert the given region at it's suitable (sorted) place.

        Args:
            region (CodeRegion): new code region to be inserted
        """
        # Check if we are the first (the easy case)
        if len(self._regions) == 0:
            # Insert the element
            self._regions.append(region)
            return
        # Check if we can merge them together
        prev_region = self._regions[-1]
        if prev_region.end == region.start and prev_region.code_type == region.code_type:
            prev_region.end = region.end
        # Otherwise, insert and link the region
        else:
            prev_region.link(region)
            self._regions.append(region)

    def convert(self, region, new_code_type):
        """Convert the given code region into the new code type, and propagate this change.

        Args:
            region (CodeRegion): given code range to change
            new_code_type (int): new code type for the region
        """
        removed_regions = []
        region.changed = True
        # merge with previous
        if region.prev is not None and region.prev.code_type == new_code_type:
            # no need to mark the prev as changed, because he won't be interesting for the heuristics
            region.prev.end = region.end
            if region.next is not None:
                region.prev.next = region.next
                region.next.prev = region.prev
            else:
                region.prev.next = None
            removed_regions.append(region)
            # Updating the current region to be the merged prev region
            region = region.prev
        # merge with next
        if region.next is not None and region.next.code_type == new_code_type:
            # no need to mark the next as changed, simply keep the current status
            region.next.changed = region.changed
            region.next.start = region.start
            if region.prev is not None:
                region.prev.next = region.next
                region.next.prev = region.prev
            else:
                region.next.prev = None
            removed_regions.append(region)
        # remove / simple change myself
        if len(removed_regions) == 0:
            region.code_type = new_code_type
        else:
            for removed in removed_regions:
                self._regions.remove(removed)

    def resizeStart(self, region, new_start):
        """Resize the region, and modify it's start.

        Args:
            region (CodeRegion): region to be resized (downward)
            new_start (int): new effective address for the region's start
        """
        region.resizeStart(new_start)
        # check if we shrunk the previous region too much (size 0)
        if region.prev is not None and region.prev.end == region.prev.start:
            removed = region.prev
            # fix the links
            if removed.prev is not None:
                removed.prev.next = region
            region.prev = removed.prev
            # remove the region
            self._regions.remove(removed)
            # now check if we also need to merge the two together
            if region.prev is not None and region.code_type == region.prev.code_type:
                region.prev.end = region.end
                region.prev.next = region.next
                if region.next is not None:
                    region.next.prev = region.prev
                # keeping the "change" status of the prev region
                self._regions.remove(region)

    def changedRegions(self):
        """Return a list of all modified code regions.

        Return value:
            list of all modified code regions since initialization
        """
        return filter(lambda x: x.changed, self._regions)

from sklearn                    import metrics
from sklearn.ensemble           import RandomForestClassifier
from sklearn.model_selection    import train_test_split
import idc
import ida_nalt
import sark
import numpy
import struct
import time

#######################
## Static Thresholds ##
#######################

CALIBRATION_LOWER_BOUND   = 0.75  # Classifiers below this threshold are not stable enough :(
CALIBRATION_UPPER_BOUND   = 0.96  # Classifiers above this threshold shouldn't be calibrated any more
CALIBRATION_TIME_ESTIMATE = 10    # Calibration that takes mora than this amount (in seconds) could get optimized

class FeatureClassifier():
    """A Random-Forest (Machine Learning) Based classifier for function related features.

    Attributes
    ----------
        _analyzer (instance): analyzer instance that we are linked to
        _name (str): name of the classified feature
        _feature_size (int): size of the feature set that we use after calibration
        _inner_offset (int): calibration offset between a feature to a non-feature
        _classifier_offsets (list): feature byte offsets
        _classifier (classifier): the actual classifier
        _interest (lambda): sark function => interesting feature
        _tag (lambda): ea => tagged meaning
        _needs_calibration (bool): False iff no more calibration rounds are needed
        _needs_training (bool): False iff no more training rounds are needed

    Notes
    -----
        1. Testing shows that byte-based classifiers work good enough, we don't need anything fancy
        2. We calibrate each classifier using a larger than needed feature set, and then dynamically pick
           the most meaningful bytes until we reach the desired feature set size.
        3. Step #2 enables us to partially handle endianness changes / architecture changes
        4. Using any Machine Learning based classifier mandates that we have a large enough data data set.
           In our case, if we don't have enough functions to calibrate to the CALIBRATION_LOWER_BOUND threshold,
           we will need to abort to avoid taking risky decisions.
    """

    def __init__(self, analyzer, name, feature_size, inner_offset, classifier_offsets, interest, tag):
        """Create the function classifier according to the architecture-based configurations.

        Args:
            analyzer (instance): analyzer instance that we are going to link against
            name (str): Name for this classifier
            feature_size (int): size of the feature set that we use after calibration
            inner_offset (int): calibration offset between a feature and a non-feature
            classifier_offsets (list): feature byte offsets
            interest (lambda): sark function => interesting feature
            tag (lambda): ea => tagged meaning
        """
        self._analyzer = analyzer
        self._name = name
        self._feature_size = feature_size
        self._inner_offset = inner_offset
        self._classifier_offsets = classifier_offsets
        self._interest = interest
        self._tag = tag
        self._classifier = None
        self._needs_calibration = True
        self._needs_training = True

    def extractSample(self, ea):
        """Extract features for a sample.

        Args:
            ea (int): effective address to be sampled

        Return Value:
            feature set (list of byte values)
        """
        return [idc.get_wide_byte(ea + o) for o in self._classifier_offsets]

    def train(self, scoped_functions):
        """Train the classifier on the scoped functions.

        Args:
            scoped_functions (list): list of all relevant (scoped) functions

        Note:
            Training must happen *after* the calibration phase
        """
        # init
        clf = RandomForestClassifier(n_estimators=100)
        eas = [self._interest(x) for x in scoped_functions] + [self._interest(x) + self._inner_offset for x in scoped_functions]
        data_set = [self.extractSample(x) for x in eas]
        data_results = [self._tag(x) for x in eas]
        # classify
        clf.fit(data_set, data_results)
        # store the result
        self._classifier = clf

    def calibrate(self, scoped_functions):
        """Calibrate the classifier on the scoped functions.

        Args:
            scoped_functions (list): list of all relevant (scoped) functions

        Notes
        -----
            1. Must include enough samples, otherwise an error will be raised

        Return Value:
            Calibration accuracy
        """
        round_names = ("Calibration", "Testing")
        # 1st round - calibration
        # 2nd round - test
        for training_round in range(len(round_names)):
            round_name = round_names[training_round]
            # Start of function classifier
            clf = RandomForestClassifier(n_estimators=100)
            eas = [self._interest(x) for x in scoped_functions] + [self._interest(x) + self._inner_offset for x in scoped_functions]
            data_set = [self.extractSample(x) for x in eas]
            data_results = [self._tag(x) for x in eas]
            # split to train and test (70%, 30%)
            X_train, X_test, Y_train, Y_test = train_test_split(data_set, data_results, test_size=0.7, random_state=5)
            # classify
            clf.fit(X_train, Y_train)
            # test
            Y_pred = clf.predict(X_test)
            accuracy = metrics.accuracy_score(Y_test, Y_pred)
            self._analyzer.logger.info(f"{round_name}: {self._name} Accuracy: {accuracy * 100:.2f}%")
            # Pick up the best features, and use only them (only needed in the first round)
            if training_round == 0:
                impact = list(zip(self._classifier_offsets, clf.feature_importances_))
                impact.sort(key=lambda x: x[1], reverse=True)
                self._classifier_offsets = [x[0] for x in impact[:self._feature_size]]
            elif accuracy < CALIBRATION_LOWER_BOUND:
                self._analyzer.logger.error(f"{self._name} Accuracy is too low, can't continue: {accuracy * 100:.2f}% < {CALIBRATION_LOWER_BOUND * 100:.2f}%")
                raise ValueError

        # Return the calibration accuracy
        return accuracy

    def prepare(self, scoped_functions):
        """Calibrate and train the classifier on the scoped functions.

        Args:
            scoped_functions (list): list of all relevant (scoped) functions

        Notes
        -----
            1. Raises a ValueError exception if the calibration failed
        """
        if not self._needs_training:
            self._analyzer.logger.info(f"{self._name} Accuracy is good enough, skipping re-training")
            return
        if self._needs_calibration:
            start_time = time.time()
            accuracy = self.calibrate(scoped_functions)
            end_time = time.time()
            self._needs_calibration = False
            if end_time - start_time >= CALIBRATION_TIME_ESTIMATE and accuracy >= CALIBRATION_UPPER_BOUND:
                self._needs_training = False
        self._analyzer.logger.info(f"{self._name} - re-train the model on the new dataset")
        self.train(scoped_functions)

    def predict(self, ea):
        """Predict the feature of the function.

        Args:
            ea (int): effective address to query

        Return Value:
            Classifier determined result
        """
        return self._classifier.predict([self.extractSample(ea)])

class FunctionClassifier():
    """A Random-Forest (Machine Learning) Based classifier for all function related features.

    Attributes
    ----------
        _analyzer (instance): analyzer instance that we are linked to
        _classifiers_start (dict): function start mapping: code type ==> classifier
        _classifiers_end (dict): function end mapping: code type ==> classifier
        _classifiers_mixed (dict): function start/end mapping: code type ==> classifier
        _classifier_type (classifier): function code type classifier

    Notes
    -----
        1. Testing shows that byte-based classifiers work good enough, we don't need anything fancy
        2. We calibrate each classifier using a larger than needed feature set, and then dynamically pick
           the most meaningful bytes until we reach the desired feature set size.
        3. Step #2 enables us to partially handle endianness changes / architecture changes
        4. Using any Machine Learning based classifier mandates that we have a large enough data data set.
           In our case, if we don't have enough functions to calibrate to the CALIBRATION_LOWER_BOUND threshold,
           we will need to abort to avoid taking risky decisions.
    """

    def __init__(self, analyzer, feature_size, inner_offset, classifiers_start_offsets, classifiers_end_offsets, classifiers_mixed_offsets, classifier_type_offsets):
        """Create the function classifier according to the architecture-based configurations.

        Args:
            analyzer (instance): analyzer instance that we are going to link against
            feature_size (int): size of the feature set that we use after calibration
            inner_offset (int): calibration offset between a feature and a non-feature
            classifiers_start_offsets (dict): initial function start mapping: code type ==> feature byte offsets
            classifiers_end_offsets (dict): initial function end mapping: code type ==> feature byte offsets
            classifiers_mixed_offsets (dict): initial function start/end mapping: code type ==> feature byte offsets
            classifiers_type_offsets (list): initial function type: feature byte offsets
        """
        self._analyzer = analyzer

        # Init all sub-classifiers
        self._classifiers_start = {}
        self._classifiers_end = {}
        self._classifiers_mixed = {}
        for code_type in self._analyzer.activeCodeTypes():
            self._classifiers_start[code_type] = FeatureClassifier(analyzer, "Function Prologue", feature_size, inner_offset, \
                                                                   classifiers_start_offsets[code_type], lambda x: x.start_ea, lambda x: int(FunctionClassifier.isFuncStart(x)))
            self._classifiers_end[code_type] = FeatureClassifier(analyzer, "Function Epilogue", feature_size, inner_offset, \
                                                                   classifiers_end_offsets[code_type], lambda x: x.end_ea, lambda x: int(FunctionClassifier.isFuncEnd(x)))
            self._classifiers_mixed[code_type] = FeatureClassifier(analyzer, "Function Prologue/Epilogue", feature_size, inner_offset, \
                                                                   classifiers_mixed_offsets[code_type], lambda x: x.start_ea, lambda x: int(FunctionClassifier.isFuncStart(x)))
        # And now, the type classifier
        if analyzer.hasActiveCodeTypes():
            self._classifier_type = FeatureClassifier(analyzer, "Function Type", feature_size, inner_offset, classifier_type_offsets, lambda x: x.start_ea, lambda x: self._analyzer.codeType(x))
        # seed the random generator
        numpy.random.seed(seed=struct.unpack("!I", ida_nalt.retrieve_input_file_md5()[:4])[0])

    @staticmethod
    def isFuncStart(ea):
        """Check if the given effective address is the start of a known function.

        Args:
            ea (int): effective address to be checked

        Return Value:
            True iff the given address is the start of a known function
        """
        try:
            return ea == sark.Function(ea).start_ea
        except sark.exceptions.SarkNoFunction:
            return False

    @staticmethod
    def isFuncEnd(ea):
        """Check if the given effective address is the end of a known function.

        Args:
            ea (int): effective address to be checked

        Return Value:
            True iff the given address is the end of a known function
        """
        prev_line = sark.Line(ea).prev
        try:
            return ea == sark.Function(prev_line.start_ea).end_ea
        except sark.exceptions.SarkNoFunction:
            return False

    def prepare(self, scs):
        """Calibrate and train all function classifiers, according to all known code segments.

        Args:
            scs (list): list of all known (sark) code segments

        Notes
        -----
            1. Each code type most include enough samples, if exists
            2. If the code type wasn't found, we will ignore it for the rest of the execution
            3. If not even a single code type was (we have 0 functions), we will raise an error

        Return Value:
            True iff the calibration passed and the accuracy is above the minimal threshold
        """
        functions = []
        for sc in scs:
            functions += [f for f in sc.functions if not self._analyzer.fptr_identifier.isPointedFunction(f.start_ea)]
        for code_type in self._analyzer.activeCodeTypes():
            scoped_functions = [x for x in functions if self._analyzer.codeType(x.start_ea) == code_type]
            self._analyzer.logger.info(f"There are {len(scoped_functions)} scoped functions for code type {code_type}")

            try:
                self._classifiers_start[code_type].prepare(scoped_functions)
                self._classifiers_end[code_type].prepare(scoped_functions)
                self._classifiers_mixed[code_type].prepare(scoped_functions)
            # ValueError when we only have a single sample and we call fit() / the accuracy is too low
            except ValueError:
                self._analyzer.logger.warning(f"Not enough functions to calibrate the classifier for code type {code_type}")
                self._analyzer.logger.warning(f"Disabling heuristics for code type {code_type}")
                self._analyzer.disableCodeType(code_type)

        # Don't forget the code types
        if self._analyzer.hasActiveCodeTypes():
            try:
                self._classifier_type.prepare(scoped_functions)
            except ValueError:
                return False

        # If reached this point it means that all was OK, if we have some code types left
        return len(self._analyzer.activeCodeTypes()) > 0

    def predictFunctionStart(self, ea, known_type=None):
        """Predict if the given address is a function start.

        Args:
            ea (int): effective address to query
            known_type (int, optional): known code type (None by default)

        Note:
            This classifier is less stable then predictFunctionStartMixed().
            Use it only when you suspect a code transition, making the data before us unstable.

        Return Value:
            True iff the classifier determined that this is a function start
        """
        code_type = self._analyzer.codeType(ea) if known_type is None else known_type
        return self._classifiers_start[code_type].predict(ea)

    def predictFunctionEnd(self, ea, known_type=None):
        """Predict if the given address is a function end.

        Args:
            ea (int): effective address to query
            known_type (int, optional): known code type (None by default)

        Return Value:
            True iff the classifier determined that this is a function end
        """
        code_type = self._analyzer.codeType(ea) if known_type is None else known_type
        return self._classifiers_end[code_type].predict(ea)

    def predictFunctionStartMixed(self, ea, known_type=None):
        """Predict if the given address is a mixed function start/end.

        Args:
            ea (int): effective address to query
            known_type (int, optional): known code type (None by default)

        Return Value:
            True iff the classifier determined that this is a function start/end
        """
        code_type = self._analyzer.codeType(ea) if known_type is None else known_type
        return self._classifiers_mixed[code_type].predict(ea)

    def predictFunctionStartType(self, ea):
        """Predict the code type of the function start.

        Args:
            ea (int): effective address to query

        Return Value:
            Classifier determined code type
        """
        # Nothing to check if there is only one type
        if not self._analyzer.hasActiveCodeTypes():
            return self._analyzer.activeCodeTypes()[0]
        # Multiple types, now predict the right one
        return int(self._classifier_type.predict(ea))

    def functionStartSize(self):
        """Get the function start size needed for a "start" sample.

        Return Value:
            Number of chunk needed to properly extract a function "start" sample
        """
        return max([max(c._classifier_offsets) for c in self._classifiers_start.values()]) + 1

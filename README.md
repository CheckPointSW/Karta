# LibSeeker

IDA Python plugin that identifies the used open source libraries in a given .idb.
If the open source is supported, it will try match and identify it's functions using a pre-compiled version,
that was compiled from the sources themselves.

The matching algorithm is location-driven. This means that it's main focus is to locate
the different compiled files, and match each of the file's functions based on their original order.
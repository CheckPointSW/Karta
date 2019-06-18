from sklearn                    import metrics
from sklearn.ensemble           import RandomForestClassifier
from sklearn.model_selection    import train_test_split
import idc
import idautils
import sark
import numpy

#######################
## Static Thresholds ##
#######################

CALIBRATION_LOWER_BOUND = 0.75  # Classifiers below this threshold are not stable enough :(

class FunctionClassifier():
    """A Random-Forest (Machine Learning) Based classifier for all function related features.

    Attributes
    ----------
        _analyzer (instance): analyzer instance that we are linked to
        _feature_size (int): size of the feature set that we use after calibration
        _inner_offset (int): calibration offset between a feature to a non-feature
        _classifiers_start_offsets (dict): function start mapping: code type ==> feature byte offsets
        _classifiers_end_offsets (dict): function end mapping: code type ==> feature byte offsets
        _classifiers_mixed_offsets (dict): function start/end mapping: code type ==> feature byte offsets
        _classifiers_type_offsets (list): function type: feature byte offsets
        _start_classifiers (dict): function start mapping: code type ==> classifier
        _end_classifiers (dict): function end mapping: code type ==> classifier
        _mixed_classifiers (dict): function start/end mapping: code type ==> classifier
        _type_classifier (classifier): function code type classifier

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
        self._feature_size = feature_size
        self._inner_offset = inner_offset
        self._classifiers_start_offsets = classifiers_start_offsets
        self._classifiers_end_offsets   = classifiers_end_offsets
        self._classifiers_mixed_offsets = classifiers_mixed_offsets
        self._classifier_type_offsets   = classifier_type_offsets
        self._start_classifiers = {}
        self._end_classifiers   = {}
        self._mixed_classifiers = {}
        self._type_classifier   = None
        # seed the random generator
        numpy.random.seed(seed=(int(idautils.GetInputFileMD5(), 16) & 0xFFFFFFFF))

    def isFuncStart(self, ea):
        """Check if the given effective address is the start of a known function.

        Args:
            ea (int): effective address to be checked

        Return Value:
            True iff the given address is the start of a known function
        """
        try:
            return ea == sark.Function(ea).startEA
        except sark.exceptions.SarkNoFunction:
            return False

    def isFuncEnd(self, ea):
        """Check if the given effective address is the end of a known function.

        Args:
            ea (int): effective address to be checked

        Return Value:
            True iff the given address is the end of a known function
        """
        prev_line = sark.Line(ea).prev
        try:
            return ea == sark.Function(prev_line.startEA).endEA
        except sark.exceptions.SarkNoFunction:
            return False

    def extractFunctionStartSample(self, ea, code_type):
        """Extract features for a "function start" sample.

        Args:
            ea (int): effective address to be sampled
            code_type (int): code type of the wanted sample

        Return Value:
            feature set (list of byte values)
        """
        return map(lambda o: idc.Byte(ea + o), self._classifiers_start_offsets[code_type])

    def extractFunctionEndSample(self, ea, code_type):
        """Extract features for a "function end" sample.

        Args:
            ea (int): effective address to be sampled
            code_type (int): code type of the wanted sample

        Return Value:
            feature set (list of byte values)
        """
        return map(lambda o: idc.Byte(ea + o), self._classifiers_end_offsets[code_type])

    def extractFunctionMixedSample(self, ea, code_type):
        """Extract features for a "function start/end" sample.

        Args:
            ea (int): effective address to be sampled
            code_type (int): code type of the wanted sample

        Return Value:
            feature set (list of byte values)
        """
        return map(lambda o: idc.Byte(ea + o), self._classifiers_mixed_offsets[code_type])

    def extractFunctionTypeSample(self, ea):
        """Extract features for a "code type" sample.

        Args:
            ea (int): effective address to be sampled

        Return Value:
            feature set (list of byte values)
        """
        return map(lambda o: idc.Byte(ea + o), self._classifier_type_offsets)

    def trainFunctionClassifier(self, scs):
        """Train all function classifiers, according to all known code segments.

        Args:
            scs (list): list of all known (sark) code segments

        Note:
            Training must happen *after* the calibration phase
        """
        functions = []
        # TODO: check if the loss of samples is worth the risk of training on questionable fptr data
        for sc in scs:
            functions += filter(lambda func: not self._analyzer.fptr_identifier.isPointedFunction(func.startEA), sc.functions)
        # Each code type is trained on it's own
        for code_type in self._analyzer.codeTypes():
            scoped_functions = filter(lambda x: self._analyzer.codeType(x.startEA) == code_type, functions)
            # Start of function classifier
            clf = RandomForestClassifier(n_estimators=100)
            eas = map(lambda x: x.startEA, scoped_functions) + map(lambda x: x.startEA + self._inner_offset, scoped_functions)
            data_set = map(lambda x: self.extractFunctionStartSample(x, code_type), eas)
            data_results = map(lambda x: 1 if self.isFuncStart(x) else 0, eas)
            # classify
            clf.fit(data_set, data_results)
            # store the results
            self._start_classifiers[code_type] = clf
            # End of function classifier
            clf = RandomForestClassifier(n_estimators=100)
            eas = map(lambda x: x.endEA, scoped_functions) + map(lambda x: x.endEA - self._inner_offset, scoped_functions)
            data_set = map(lambda x: self.extractFunctionEndSample(x, code_type), eas)
            data_results = map(lambda x: 1 if self.isFuncEnd(x) else 0, eas)
            # classify
            clf.fit(data_set, data_results)
            # store the results
            self._end_classifiers[code_type] = clf
            # Start/End of function classifier
            clf = RandomForestClassifier(n_estimators=100)
            eas = map(lambda x: x.startEA, scoped_functions) + map(lambda x: x.startEA + self._inner_offset, scoped_functions)
            data_set = map(lambda x: self.extractFunctionMixedSample(x, code_type), eas)
            data_results = map(lambda x: 1 if self.isFuncStart(x) else 0, eas)
            # classify
            clf.fit(data_set, data_results)
            # store the results
            self._mixed_classifiers[code_type] = clf

    def calibrateFunctionClassifier(self, scs):
        """Calibrate all function classifiers, according to all known code segments.

        Args:
            scs (list): list of all known (sark) code segments

        Return Value:
            True iff the calibration passed and the accuracy is above the minimal threshold
        """
        functions = []
        # TODO: check if the loss of samples is worth the risk of training on questionable fptr data
        for sc in scs:
            functions += filter(lambda func: not self._analyzer.fptr_identifier.isPointedFunction(func.startEA), sc.functions)
        for code_type in self._analyzer.codeTypes():
            scoped_functions = filter(lambda x: self._analyzer.codeType(x.startEA) == code_type, functions)
            self._analyzer.logger.info("There are %d scoped functions for code type %d", len(scoped_functions), code_type)
            # 1st round - calibration
            # 2nd round - test
            for training_round in xrange(2):
                round_name = "Calibration" if training_round == 0 else "Testing"
                # Start of function classifier
                clf = RandomForestClassifier(n_estimators=100)
                eas = map(lambda x: x.startEA, scoped_functions) + map(lambda x: x.startEA + self._inner_offset, scoped_functions)
                data_set = map(lambda x: self.extractFunctionStartSample(x, code_type), eas)
                data_results = map(lambda x: 1 if self.isFuncStart(x) else 0, eas)
                # split to train and test (70%, 30%)
                X_train, X_test, Y_train, Y_test = train_test_split(data_set, data_results, test_size=0.7, random_state=5)
                # classify
                clf.fit(X_train, Y_train)
                # test
                Y_pred = clf.predict(X_test)
                accuracy = metrics.accuracy_score(Y_test, Y_pred)
                self._analyzer.logger.info("%s: Function Prologue Accuracy: %.2f%%", round_name, accuracy * 100)
                # Pick up the best features, and use only them (only needed in the first round)
                if training_round == 0:
                    start_impact = zip(self._classifiers_start_offsets[code_type], clf.feature_importances_)
                    start_impact.sort(key=lambda x: x[1], reverse=True)
                    self._classifiers_start_offsets[code_type] = map(lambda x: x[0], start_impact[:self._feature_size])
                elif accuracy < CALIBRATION_LOWER_BOUND:
                    self._analyzer.logger.error("Function Prologue Accuracy is too low, can't continue: %.2f%% < %.2f%%", accuracy * 100, CALIBRATION_LOWER_BOUND * 100)
                    return False
                # End of function classifier
                clf = RandomForestClassifier(n_estimators=100)
                eas = map(lambda x: x.endEA, scoped_functions) + map(lambda x: x.endEA - self._inner_offset, scoped_functions)
                data_set = map(lambda x: self.extractFunctionEndSample(x, code_type), eas)
                data_results = map(lambda x: 1 if self.isFuncEnd(x) else 0, eas)
                # split to train and test (70%, 30%)
                X_train, X_test, Y_train, Y_test = train_test_split(data_set, data_results, test_size=0.7, random_state=5)
                # classify
                clf.fit(X_train, Y_train)
                # test
                Y_pred = clf.predict(X_test)
                accuracy = metrics.accuracy_score(Y_test, Y_pred)
                self._analyzer.logger.info("%s: Function Epilogue Accuracy: %.2f%%", round_name, accuracy * 100)
                # Pick up the best features, and use only them (only needed in the first round)
                if training_round == 0:
                    end_impact = zip(self._classifiers_end_offsets[code_type], clf.feature_importances_)
                    end_impact.sort(key=lambda x: x[1], reverse=True)
                    self._classifiers_end_offsets[code_type] = map(lambda x: x[0], end_impact[:self._feature_size])
                elif accuracy < CALIBRATION_LOWER_BOUND:
                    self._analyzer.logger.error("Function Epilogue Accuracy is too low, can't continue: %.2f%% < %.2f%%", accuracy * 100, CALIBRATION_LOWER_BOUND * 100)
                    return False
                # Start/End of function classifier
                clf = RandomForestClassifier(n_estimators=100)
                eas = map(lambda x: x.startEA, scoped_functions) + map(lambda x: x.startEA + self._inner_offset, scoped_functions)
                data_set = map(lambda x: self.extractFunctionMixedSample(x, code_type), eas)
                data_results = map(lambda x: 1 if self.isFuncStart(x) else 0, eas)
                # split to train and test (70%, 30%)
                X_train, X_test, Y_train, Y_test = train_test_split(data_set, data_results, test_size=0.7, random_state=5)
                # classify
                clf.fit(X_train, Y_train)
                # test
                Y_pred = clf.predict(X_test)
                accuracy = metrics.accuracy_score(Y_test, Y_pred)
                self._analyzer.logger.info("%s: Function Prologue/Epilogue Accuracy: %.2f%%", round_name, accuracy * 100)
                # Pick up the best features, and use only them (only needed in the first round)
                if training_round == 0:
                    mixed_impact = zip(self._classifiers_mixed_offsets[code_type], clf.feature_importances_)
                    mixed_impact.sort(key=lambda x: x[1], reverse=True)
                    self._classifiers_mixed_offsets[code_type] = map(lambda x: x[0], mixed_impact[:self._feature_size])
                elif accuracy < CALIBRATION_LOWER_BOUND:
                    self._analyzer.logger.error("Function Prologue/Epilogue Accuracy is too low, can't continue: %.2f%% < %.2f%%", accuracy * 100, CALIBRATION_LOWER_BOUND * 100)
                    return False
        # If reached this point it means that all was OK
        return True

    def trainFunctionTypeClassifier(self, scs):
        """Train the type classifier, according to all known code segments.

        Args:
            scs (list): list of all known (sark) code segments

        Note:
            Training must happen *after* the calibration phase
        """
        functions = []
        for sc in scs:
            functions += filter(lambda func: not self._analyzer.fptr_identifier.isPointedFunction(func.startEA), sc.functions)
        clf = RandomForestClassifier(n_estimators=100)
        eas = map(lambda x: x.startEA, functions)
        data_set = map(self.extractFunctionTypeSample, eas)
        data_results = map(self._analyzer.codeType, eas)
        # classify
        clf.fit(data_set, data_results)
        # store the results
        self._type_classifier = clf

    def calibrateFunctionTypeClassifier(self, scs):
        """Calibrate the type classifier, according to all known code segments.

        Args:
            scs (list): list of all known (sark) code segments

        Return Value:
            True iff the calibration was successfully and is more accurate than the assigned lower bound
        """
        functions = []
        for sc in scs:
            functions += filter(lambda func: not self._analyzer.fptr_identifier.isPointedFunction(func.startEA), sc.functions)
        # 1st round - calibration
        # 2nd round - test
        for training_round in xrange(2):
            round_name = "Calibration" if training_round == 0 else "Testing"
            clf = RandomForestClassifier(n_estimators=100)
            eas = map(lambda x: x.startEA, functions)
            data_set = map(self.extractFunctionTypeSample, eas)
            data_results = map(self._analyzer.codeType, eas)
            # split to train and test (70%, 30%)
            X_train, X_test, Y_train, Y_test = train_test_split(data_set, data_results, test_size=0.7, random_state=5)
            # classify
            clf.fit(X_train, Y_train)
            # test
            Y_pred = clf.predict(X_test)
            accuracy = metrics.accuracy_score(Y_test, Y_pred)
            self._analyzer.logger.info("%s: Function accuracy Type Accuracy: %.2f%%", round_name, accuracy * 100)
            # Pick up the best features, and use only them (only needed in the first round)
            if training_round == 0:
                type_impact = zip(self._classifier_type_offsets, clf.feature_importances_)
                type_impact.sort(key=lambda x: x[1], reverse=True)
                self._classifier_type_offsets = map(lambda x: x[0], type_impact[:self._feature_size])
            elif accuracy < CALIBRATION_LOWER_BOUND:
                self._analyzer.logger.error("Function Prologue Type Accuracy is too low, can't continue: %.2f%% < %.2f%%", accuracy * 100, CALIBRATION_LOWER_BOUND * 100)
                return False
        # If reached this point it means that all was OK
        return True

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
        if known_type is None:
            code_type = self._analyzer.codeType(ea)
        else:
            code_type = known_type
        sample = self.extractFunctionStartSample(ea, code_type)
        return self._start_classifiers[code_type].predict([sample])

    def predictFunctionEnd(self, ea, known_type=None):
        """Predict if the given address is a function end.

        Args:
            ea (int): effective address to query
            known_type (int, optional): known code type (None by default)

        Return Value:
            True iff the classifier determined that this is a function end
        """
        if known_type is None:
            code_type = self._analyzer.codeType(ea)
        else:
            code_type = known_type
        sample = self.extractFunctionEndSample(ea, code_type)
        return self._end_classifiers[code_type].predict([sample])

    def predictFunctionStartMixed(self, ea, known_type=None):
        """Predict if the given address is a mixed function start/end.

        Args:
            ea (int): effective address to query
            known_type (int, optional): known code type (None by default)

        Return Value:
            True iff the classifier determined that this is a function start/end
        """
        if known_type is None:
            code_type = self._analyzer.codeType(ea)
        else:
            code_type = known_type
        sample = self.extractFunctionMixedSample(ea, code_type)
        return self._mixed_classifiers[code_type].predict([sample])

    def predictFunctionStartType(self, ea):
        """Predict the code type of the function start.

        Args:
            ea (int): effective address to query

        Return Value:
            Classifier determined code type
        """
        # Nothing to check if there is only one type
        if not self._analyzer.hasCodeTypes():
            return self._analyzer.codeTypes()[0]
        # Multiple types, now predict the right one
        sample = self.extractFunctionTypeSample(ea)
        return int(self._type_classifier.predict([sample]))

    def functionStartSize(self):
        """Get the function start size needed for a "start" sample.

        Return Value:
            Number of chunk needed to properly extract a function "start" sample
        """
        return max(map(max, self._classifiers_start_offsets.values())) + 1

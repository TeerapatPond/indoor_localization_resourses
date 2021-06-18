from sklearn import svm
from sklearn.metrics.pairwise import cosine_similarity
from numpy import array
import numpy


class SVM_BLD:
    def __init__(self, is_calibrate, training_data, testing_data, missing_access_points=None):
        self.is_calibrate = is_calibrate
        self.raw_training_data = training_data
        self.raw_testing_data = testing_data
        self.missing_access_points = missing_access_points
        self.adaptive()  # For my adaptive algorithm
        self.training_data = []
        self.training_data_label = []
        self.model = None
        self.testing_data = []
        self.universe_ap = []
        self.create_universe_ap()

    def adaptive(self):
        for t in self.raw_training_data:  # Removed APs detection
            size = len(t['access_point'])
            for i in range(size - 1, -1, -1):
                if not self.missing_access_points is None:  # TODO Added in python3
                    if t['access_point'][i]['BSSID'] in self.missing_access_points:
                        del t['access_point'][i]

    def create_universe_ap(self):
        for t in self.raw_training_data:
            if t['environment'] == 'indoor':
                for ap in t['access_point']:
                    if ap['BSSID'] not in self.universe_ap:
                        self.universe_ap.append(ap['BSSID'])

    def dbm_to_mw(self, dbm):
        return dbm
        # return 10 ** (float(dbm) / 10)

    def feature_extraction(self, access_point):
        rssi_index = [0] * len(self.universe_ap)
        for ap in access_point:
            if ap['BSSID'] in self.universe_ap:
                ind = self.universe_ap.index(ap['BSSID'])
                rssi_index[ind] = self.dbm_to_mw(int(ap['RSSI']))
        return rssi_index

    def calibrate(self, target):
        if self.is_calibrate:
            similar_fingerprint = []
            for f in self.training_data:
                cosine_sim = cosine_similarity(array(target).reshape(1, -1), array(f).reshape(1, -1))[0][0]
                if cosine_sim > 0.95:
                    similar_fingerprint.append(f)
            if len(similar_fingerprint) > 0:
                x = []
                y = []
                for s in similar_fingerprint:
                    x += target
                    y += s
                x = array(x)
                y = array(y)
                A = numpy.vstack([x, numpy.ones(len(x))]).T
                m, c = numpy.linalg.lstsq(A, y, rcond=None)[0]
                calibrated_target = []
                for t in target:
                    if t == 0:
                        calibrated_target.append(t)
                    else:
                        calibrated_target.append(m * t + c)
                return calibrated_target
            else:
                return target
        else:
            return target

    def create_fingerprint(self):
        for t in self.raw_training_data:
            if t['environment'] == 'indoor':
                self.training_data.append(self.feature_extraction(t['access_point']))
                self.training_data_label.append(t['building_id'])

        self.model = svm.SVC(C=1.0, cache_size=200, class_weight=None, coef0=0.0,
                             decision_function_shape='ovr', degree=1, gamma='auto', kernel='linear',
                             max_iter=1000, probability=True, random_state=None, shrinking=True,
                             tol=0.001, verbose=False)
        self.model.fit(self.training_data, self.training_data_label)

        for t in self.raw_testing_data:
            if t['environment'] == 'indoor':
                t['feature'] = self.calibrate(self.feature_extraction(t['access_point']))
                self.testing_data.append(t)

    def predict_all(self):
        predicted_result = []
        for sampling in self.testing_data:
            s = sampling['feature']
            predicted_building = self.model.predict([s])[0]
            predicted_result.append(
                {'key_building_id': sampling['building_id'],
                 'key_tag': sampling['tag'], 'key_floor': sampling['floor'],
                 'predicted_building_id': [predicted_building]})
        return predicted_result

    def predict_once(self, sampling):
        feature = self.calibrate(self.feature_extraction(sampling))
        predicted_building = self.model.predict([feature])[0]
        return [predicted_building]
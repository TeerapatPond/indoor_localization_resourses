from sklearn.decomposition import PCA
from sklearn.metrics.pairwise import cosine_similarity
from numpy import array
import numpy


class PCA_IO:
    def __init__(self, k, is_calibrate, training_data, testing_data, missing_access_points=None):
        self.k = k
        self.is_calibrate = is_calibrate
        self.raw_training_data = training_data
        self.raw_testing_data = testing_data
        self.missing_access_points = missing_access_points
        self.adaptive()  # For my adaptive algorithm
        self.training_data = []
        self.testing_data = []
        self.model = None
        self.threshold = 0
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
                m, c = numpy.linalg.lstsq(A, y)[0]
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

    def reconstruction_error(self, feature):
        proj = self.model.transform(array(feature).reshape(1, -1))
        proj_back = self.model.inverse_transform(proj)

        diff = feature - proj_back
        sum = 0.0
        for i in range(0, len(diff[0])):
            sum += diff[0][i] * diff[0][i]
        return sum

    def create_fingerprint(self):
        for t in self.raw_training_data:
            if t['environment'] == 'indoor':
                if not len(t['access_point']) == 0:
                    self.training_data.append(self.feature_extraction(t['access_point']))
        pca = PCA(n_components=self.k)
        self.model = pca.fit(self.training_data)

        training_total_error = []
        for t in self.training_data:
            training_total_error.append(self.reconstruction_error(t))
        self.threshold = numpy.max(training_total_error)

        for t in self.raw_testing_data:
            t['feature'] = self.calibrate(self.feature_extraction(t['access_point']))
            self.testing_data.append(t)

    def predict_all(self):
        predicted_result = []
        for sampling in self.testing_data:
            s = sampling['feature']

            recons_error = self.reconstruction_error(s)
            if recons_error < self.threshold:
                predicted_environment = 'indoor'
            else:
                predicted_environment = 'outdoor'

            predicted_result.append(
                {'key_environment': sampling['environment'], 'key_building_id': sampling['building_id'],
                 'key_tag': sampling['tag'], 'key_floor': sampling['floor'],
                 'predicted_environment': predicted_environment})

        return predicted_result

    def predict_once(self, sampling):
        feature = self.calibrate(self.feature_extraction(sampling))
        if all(v == 0 for v in feature):
            return 'outdoor'

        recons_error = self.reconstruction_error(feature)
        # if recons_error < self.threshold:
        if recons_error < 42369.0:
            return 'indoor'
        else:
            return 'outdoor'
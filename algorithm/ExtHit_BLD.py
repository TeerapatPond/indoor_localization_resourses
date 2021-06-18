class ExtHit_BLD:
    def __init__(self, top_n, training_data, testing_data, missing_access_points=None):
        self.top_n = top_n
        self.raw_training_data = training_data
        self.raw_testing_data = testing_data
        self.training_data = {}
        self.testing_data = []
        self.missing_access_points = missing_access_points
        # self.filter_unknown_BSSID()

    def filter_unknown_BSSID(self):
        universe_ap = set()
        for f in self.raw_training_data:
            for ap in f['access_point']:
                universe_ap.add(ap['BSSID'])

        for s in self.raw_testing_data:
            size = len(s['access_point'])
            for i in range(size - 1, -1, -1):
                if s['access_point'][i]['BSSID'] not in universe_ap:
                    del s['access_point'][i]

    def create_fingerprint(self):
        if self.missing_access_points is not None:
            for t in self.raw_training_data:  # Removed APs detection
                size = len(t['access_point'])
                for i in range(size - 1, -1, -1):
                    if t['access_point'][i]['BSSID'] in self.missing_access_points:
                        del t['access_point'][i]

        self.filter_unknown_BSSID()

        for t in self.raw_training_data:
            if t['environment'] == 'indoor':
                if t['building_id'] not in self.training_data:
                    self.training_data[t['building_id']] = set()
                self.training_data[t['building_id']].update(self.get_BSSID(t['access_point'][0:self.top_n]))

        for t in self.raw_testing_data:
            if t['environment'] == 'indoor':
                t['access_point'] = self.get_BSSID(t['access_point'][0:self.top_n])
                self.testing_data.append(t)

    def get_BSSID(self, access_point):
        bssid = []
        for ap in access_point:
            bssid.append(ap['BSSID'])
        return bssid

    def predict_all(self):
        predicted_result = []
        for sampling in self.testing_data:
            s = sampling['access_point']
            hit_score = {}
            for building in self.training_data:
                fingerprint = self.training_data[building]
                hit_score[building] = self.calculate_hit_score(fingerprint, s)
            answer = self.get_answer(hit_score)
            predicted_result.append(
                {'key_building_id': sampling['building_id'],
                 'key_tag': sampling['tag'], 'key_floor': sampling['floor'],
                 'predicted_building_id': answer['predicted_building_id']})
        return predicted_result

    def calculate_hit_score(self, fingerprint, sampling):
        hit_score = 0
        for bssid in sampling:
            if bssid in fingerprint:
                hit_score += 1
        return hit_score

    def get_answer(self, hit_score):
        max_hit_score = 0
        predicted_building_id = ['XXX']
        for building in hit_score:
            if hit_score[building] > max_hit_score:
                max_hit_score = hit_score[building]
                predicted_building_id = [building]
            elif hit_score[building] == max_hit_score and not max_hit_score == 0:
                predicted_building_id.append(building)
        return {'predicted_building_id': predicted_building_id}

    def predict_once(self, sampling):
        hit_score = {}
        for building in self.training_data:
            fingerprint = self.training_data[building]
            hit_score[building] = self.calculate_hit_score(fingerprint, self.get_BSSID(sampling[0:self.top_n]))
        answer = self.get_answer(hit_score)
        return answer['predicted_building_id']
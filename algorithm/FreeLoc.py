from datetime import datetime

class FreeLoc:
    def __init__(self, delta, training_data, testing_data, missing_access_points=None):
        self.delta = delta
        self.raw_training = training_data
        self.raw_testing = testing_data
        self.training_data = {}
        self.testing_data = []
        self.missing_access_points = missing_access_points

    def create_fingerprint(self):
        if self.missing_access_points is not None:
            for t in self.training_data:  # Removed APs detection
                size = len(t['access_point'])
                for i in range(size - 1, -1, -1):
                    if t['access_point'][i]['BSSID'] in self.missing_access_points:
                        del t['access_point'][i]

        temp_training = {}
        for t in self.raw_training:
            model = self.create_model_fingerprint(t['access_point'])
            if self.get_key(t['floor'], t['tag']) in temp_training:
                temp_training[self.get_key(t['floor'], t['tag'])].append(model)
            else:
                temp_training[self.get_key(t['floor'], t['tag'])] = [model]

        for t in self.raw_testing:
            model = self.create_model_fingerprint(t['access_point'])
            t['model'] = model
            self.testing_data.append(t)

        for k in temp_training:
            merged = self.merge_model_fingerprint(temp_training[k])
            self.training_data[k] = merged

    def get_ap_lower_delta(self, access_point, threshold):
        ap_list = []
        for a in access_point:
            if a['RSSI'] < threshold:
                ap_list.append(a['BSSID'])
        return ap_list

    def merge_model_fingerprint(self, model_list):
        merged = {}
        for m in model_list:
            for k in m:
                if k in merged:
                    for ap in m[k]:
                        if ap not in merged[k]:
                            merged[k].append(ap)
                else:
                    merged[k] = m[k]
        return merged

    def create_model_fingerprint(self, access_point):
        m = {}
        for ap in access_point:
            m[ap['BSSID']] = self.get_ap_lower_delta(access_point, ap['RSSI'] - self.delta)
        return m

    def get_key(self, floor, tag):
        return str(floor) + '-' + str(tag)

    def predict_all(self):
        predicted_result = []
        for sampling in self.testing_data:
            s = sampling['model']
            for key in self.training_data:
                model = self.training_data[key]
                self.training_data[key]['score'] = self.calculate_score(model, s)
            answer = self.get_answer()
            predicted_result.append({'key_floor': sampling['floor'], 'key_tag': sampling['tag'], 'predicted_location': answer})
        return predicted_result

    def calculate_score(self, f, s):
        score = 0
        for key in s:
            if key in f:
                for val in s[key]:
                    if val in f[key]:
                        score += 1
        return score

    def get_answer(self):
        max_score = 0
        location = []
        for key in self.training_data:
            if self.training_data[key]['score'] > max_score:
                max_score = self.training_data[key]['score']
                l = key.split('-')
                location = [{'floor': l[0], 'tag': l[1]}]
            elif self.training_data[key]['score'] == max_score:
                l = key.split('-')
                location.append({'floor': l[0], 'tag': l[1]})
        return location

    def get_hit_score(self):
        score = []
        for sampling in self.testing_data:
            s = sampling['model']
            for key in self.training_data:
                model = self.training_data[key]
                self.training_data[key]['score'] = self.calculate_score(model, s)

            sc = []
            for key in self.training_data:
                l = key.split('-')
                sc.append({'floor': l[0], 'tag': l[1], 'hit_score': self.training_data[key]['score']})

            score.append({'floor': sampling['floor'], 'tag': sampling['tag'], 'hit_score': sc})

        return score

    def processing_time(self):
        processed_time = []
        for s in self.raw_testing:
            start = datetime.now()  # Start timer
            s = self.create_model_fingerprint(s['access_point'])
            for key in self.training_data:
                model = self.training_data[key]
                self.training_data[key]['score'] = self.calculate_score(model, s)
            self.get_answer()
            end = datetime.now()  # Stop timer
            delta = end - start
            processed_time.append({'processing_time': delta.microseconds})
        return processed_time
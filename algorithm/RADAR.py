import math


class RADAR:
    def __init__(self, k, training_data, testing_data, missing_access_points=None):
        self.k = k
        self.raw_training = training_data
        self.raw_testing = testing_data
        self.training_data = []
        self.testing_data = []
        self.index_list = []
        self.missing_access_points = missing_access_points

    def create_fingerprint(self):
        if self.missing_access_points is not None:
            for t in self.raw_training:  # Removed APs detection
                size = len(t['access_point'])
                for i in range(size - 1, -1, -1):
                    if t['access_point'][i]['BSSID'] in self.missing_access_points:
                        del t['access_point'][i]

        self.create_index_list()

        for t in self.raw_training:
            model = self.create_model(t['access_point'])
            t['model'] = model
            self.training_data.append(t)

        for t in self.raw_testing:
            model = self.create_model(t['access_point'])
            t['model'] = model
            self.testing_data.append(t)

    def create_index_list(self):
        for t in self.raw_training:
            for ap in t['access_point']:
                if ap['BSSID'] not in self.index_list:
                    self.index_list.append(ap['BSSID'])

    def create_model(self, ap):
        model = [0] * len(self.index_list)
        for a in ap:
            try:
                model[self.index_list.index(a['BSSID'])] = a['RSSI']
            except ValueError:
                pass
        return model

    def predict_all(self):
        predicted_result = []
        for sampling in self.testing_data:
            s = sampling['model']
            for t in self.training_data:
                model = t['model']
                t['distance'] = self.calculate_distance(model, s)
            answer = self.get_answer()
            predicted_result.append(
                {'key_floor': sampling['floor'], 'key_tag': sampling['tag'], 'predicted_location': answer})
        return predicted_result

    def calculate_distance(self, f, s):
        distance = 0
        for i in range(0, len(s)):
            distance += (f[i] - s[i]) * (f[i] - s[i])
        return math.sqrt(distance)

    def get_answer(self):
        ordered_distance = sorted(self.training_data, key=lambda k: k['distance'], reverse=False)
        top_k = ordered_distance[0:self.k]

        tag_list = []
        temp_floor = top_k[0]['floor']
        is_same_floor = True
        for t in top_k:
            if int(t['floor']) == int(temp_floor):
                tag_list.append(int(t['tag']))
            else:
                is_same_floor = False

        tag = float(sum(tag_list)) / len(tag_list)

        if is_same_floor:
            return [{'floor': temp_floor, 'tag': tag}]
        else:
            return [{'floor': '99', 'tag': tag}]

    def get_distance(self):
        distance = []
        for sampling in self.testing_data:
            s = sampling['model']
            for t in self.training_data:
                model = t['model']
                t['distance'] = self.calculate_distance(model, s)

            dt = []
            for t in self.training_data:
                dt.append({'floor': t['floor'], 'tag': t['tag'], 'distance': t['distance']})

            distance.append({'floor': sampling['floor'], 'tag': sampling['tag'], 'distance': dt})
        return distance

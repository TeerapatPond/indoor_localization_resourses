import math


class WinIPS:
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

    def mean(self, l):
        return float(sum(l)) / len(l)

    def standard_deviation(self, l):
        mean = self.mean(l)
        variance = float(sum([((x - mean) ** 2) for x in l])) / len(l)
        return variance ** 0.5

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

        mean = self.mean(model)
        sd = self.standard_deviation(model)

        for i in range(0, len(model)):
            model[i] = (model[i] - mean) / sd

        return model

    def predict_all(self):
        predicted_result = []
        for sampling in self.testing_data:
            s = sampling['model']
            for t in self.training_data:
                model = t['model']
                t['STI'] = self.euclidean_distance(model, s)

            sum_of_divide_sti = 0.0
            for t in self.training_data:
                sum_of_divide_sti += (1.0 / (t['STI'] + 0.000001))  # Avoid division by zero

            for t in self.training_data:
                weight = (1.0 / (t['STI'] + 0.000001)) / sum_of_divide_sti
                t['weight'] = weight

            answer = self.get_answer()
            predicted_result.append(
                {'key_floor': sampling['floor'], 'key_tag': sampling['tag'], 'predicted_location': answer})
        return predicted_result

    def euclidean_distance(self, f, s):
        distance = 0.0
        for i in range(0, len(s)):
            distance += (f[i] - s[i]) * (f[i] - s[i])
        return math.sqrt(distance)

    def get_answer(self):
        ordered_distance = sorted(self.training_data, key=lambda k: k['weight'], reverse=True)  # Descending
        top_k = ordered_distance[0:self.k]

        sum_of_tag = 0.0
        sum_of_weight = 0.0
        temp_floor = top_k[0]['floor']
        is_same_floor = True

        for t in top_k:
            if int(t['floor']) == int(temp_floor):
                sum_of_tag += int(t['tag']) * t['weight']
                sum_of_weight += t['weight']
            else:
                is_same_floor = False

        tag = sum_of_tag / sum_of_weight

        if is_same_floor:
            return [{'floor': temp_floor, 'tag': tag}]
        else:
            return [{'floor': '99', 'tag': tag}]

    def get_weight(self):
        weight_list = []
        for sampling in self.testing_data:
            s = sampling['model']
            for t in self.training_data:
                model = t['model']
                t['STI'] = self.euclidean_distance(model, s)

            sum_of_divide_sti = 0.0
            for t in self.training_data:
                sum_of_divide_sti += (1.0 / (t['STI'] + 0.000001))  # Avoid division by zero

            for t in self.training_data:
                weight = (1.0 / (t['STI'] + 0.000001)) / sum_of_divide_sti  # Avoid division by zero
                t['weight'] = weight

            wt = []
            for t in self.training_data:
                wt.append({'floor': t['floor'], 'tag': t['tag'], 'weight': t['weight']})

            weight_list.append({'floor': sampling['floor'], 'tag': sampling['tag'], 'weight': wt})
        return weight_list

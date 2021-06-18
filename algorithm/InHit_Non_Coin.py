from operator import itemgetter

class InHit_Non_Coin:
    def __init__(self, top_n, rssi_diff, top_fingerprint, training_data, testing_data, missing_access_points=None):
        self.top_n = top_n
        self.rssi_diff = rssi_diff
        self.training_data = training_data
        self.testing_data = testing_data
        self.top_fingerprint = top_fingerprint
        self.missing_access_points = missing_access_points

    def create_fingerprint(self):
        if self.missing_access_points is not None:
            for t in self.training_data:  # Removed APs detection
                size = len(t['access_point'])
                for i in range(size - 1, -1, -1):
                    if t['access_point'][i]['BSSID'] in self.missing_access_points:
                        del t['access_point'][i]

        for t in self.training_data:
            t['access_point'] = t['access_point'][0:self.top_n]

        for t in self.testing_data:
            t['access_point'] = t['access_point'][0:self.top_n]

    def predict_all(self):
        predicted_result = []
        for sampling in self.testing_data:
            s = sampling['access_point']
            for fingerprint in self.training_data:
                f = fingerprint['access_point']
                fingerprint['hit_score'] = self.calculate_hit_score(f, s)
            answer = self.get_answer()
            predicted_result.append(
                {'key_floor': sampling['floor'], 'key_tag': sampling['tag'], 'predicted_location': answer})
        return predicted_result

    def calculate_hit_score(self, f, s):
        hit_score = 0
        for ap_s in s:
            for ap_f in f:
                if ap_s['BSSID'] == ap_f['BSSID']:
                    if abs(ap_s['RSSI'] - ap_f['RSSI']) <= self.rssi_diff:
                        hit_score += 1
                    break
        return hit_score

    def get_answer(self):
        hit_score = []
        for f in self.training_data:
            hit_score.append({'hit_score': f['hit_score'], 'floor': f['floor'], 'tag': int(f['tag'])})

        sorted_list = sorted(hit_score, key=itemgetter('hit_score'), reverse=True)
        most_match_fingerprint = sorted_list[0:self.top_fingerprint]

        sum_hit_score = 0
        sum_tag = 0
        for fp in most_match_fingerprint:
            sum_hit_score += fp['hit_score']
            sum_tag += (fp['tag'] * fp['hit_score'])
        final_tag = (sum_tag + 0.0) / sum_hit_score

        location = {'floor': most_match_fingerprint[0]['floor'], 'tag': final_tag}

        return location

    # def get_hit_score(self):
    #     hit_score = []
    #     for sampling in self.testing_data:
    #         s = sampling['access_point']
    #         for fingerprint in self.training_data:
    #             f = fingerprint['access_point']
    #             fingerprint['hit_score'] = self.calculate_hit_score(f, s)
    #
    #         sc = []
    #         for f in self.training_data:
    #             sc.append({'floor': f['floor'], 'tag': f['tag'], 'hit_score': f['hit_score']})
    #
    #         hit_score.append({'floor': sampling['floor'], 'tag': sampling['tag'], 'hit_score': sc})
    #
    #     return hit_score

    # def processing_time(self):
    #     processed_time = []
    #     for sampling in self.testing_data:
    #         start = datetime.now()  # Start timer
    #         s = sampling['access_point']
    #         for fingerprint in self.training_data:
    #             f = fingerprint['access_point']
    #             fingerprint['hit_score'] = self.calculate_hit_score(f, s)
    #         self.get_answer()
    #         end = datetime.now()  # Stop timer
    #         delta = end - start
    #         processed_time.append(
    #             {'processing_time': delta.microseconds})
    #     return processed_time

    # def predict_once(self, sampling, building_list):
    #     for fingerprint in self.training_data:
    #         fingerprint['hit_score'] = 0
    #         if fingerprint['building_id'] in building_list:
    #             f = fingerprint['access_point']
    #             fingerprint['hit_score'] = self.calculate_hit_score(f, sampling[0:self.top_n])
    #     answer = self.get_answer()
    #     return answer

    # def predict_once_wo_area(self, sampling):
    #     for fingerprint in self.training_data:
    #         f = fingerprint['access_point']
    #         fingerprint['hit_score'] = self.calculate_hit_score(f, sampling[0:self.top_n])
    #     answer = self.get_answer()
    #     return answer

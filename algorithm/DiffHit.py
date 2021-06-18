from datetime import datetime


class DiffHit:
    def __init__(self, top_n, training_data, testing_data, missing_access_points=None):
        self.top_n = top_n
        self.training_data = training_data
        self.testing_data = testing_data
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
        for ap_s in range(0, len(s)):
            for ap_f in range(0, len(f)):
                if s[ap_s]['BSSID'] == f[ap_f]['BSSID']:
                    d = abs(ap_s - ap_f)
                    hit_score += self.top_n - d
        return hit_score

    def get_answer(self):
        max_hit_score = 0
        location = []
        for f in self.training_data:
            if f['hit_score'] > max_hit_score:
                max_hit_score = f['hit_score']
                location = [{'floor': f['floor'], 'tag': f['tag']}]
            elif f['hit_score'] == max_hit_score:
                ###### For merge the same answer ######
                # new_location = {'floor': f['floor'], 'tag': f['tag']}
                # if new_location not in location:
                #     location.append(new_location)

                location.append({'floor': f['floor'], 'tag': f['tag']})
        return location

    def get_hit_score(self):
        hit_score = []
        for sampling in self.testing_data:
            s = sampling['access_point']
            for fingerprint in self.training_data:
                f = fingerprint['access_point']
                fingerprint['hit_score'] = self.calculate_hit_score(f, s)

            sc = []
            for f in self.training_data:
                sc.append({'floor': f['floor'], 'tag': f['tag'], 'hit_score': f['hit_score']})

            hit_score.append({'floor': sampling['floor'], 'tag': sampling['tag'], 'hit_score': sc})

        return hit_score

    def processing_time(self):
        processed_time = []
        for sampling in self.testing_data:
            start = datetime.now()  # Start timer
            s = sampling['access_point']
            for fingerprint in self.training_data:
                f = fingerprint['access_point']
                fingerprint['hit_score'] = self.calculate_hit_score(f, s)
            self.get_answer()
            end = datetime.now()  # Stop timer
            delta = end - start
            processed_time.append(
                {'processing_time': delta.microseconds})
        return processed_time

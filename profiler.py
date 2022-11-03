import time


class Profiler(object):
    def __enter__(self):
        self._startTime = time.time()
         
    def __exit__(self, type, value, traceback):
        print('Elapsed time: {:.6f} sec'.format(time.time() - self._startTime))

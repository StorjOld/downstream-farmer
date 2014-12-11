from multiprocessing import Process
from downstream_farmer.shell import main
import argparse
import time

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--number', help='Number of farmers to launch',
                        type=int, default=1)
    args = parser.parse_args()
    n = args.number
    p = dict()
    for i in range(0, n):
        p[i] = Process(target=main, args=[['--forcenew']])
        p[i].start()
        time.sleep(1)
    for i in range(0, n):
        p[i].join()

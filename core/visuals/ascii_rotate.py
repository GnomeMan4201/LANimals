#!/usr/bin/env python3
import os
import time

banners = ["LANIMALS :: INFILTRATE", "LANIMALS :: CONTROL", "LANIMALS :: ILLUSION"]


def rotate_ascii():
    for frame in banners:
        os.system("clear")
        print(f"\n\033[1;32m{frame}\033[0m")
        time.sleep(0.7)


if __name__ == "__main__":
    rotate_ascii()

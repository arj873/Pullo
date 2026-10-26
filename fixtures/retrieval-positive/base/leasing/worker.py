from leasing.scheduler import Scheduler


def run_tick(scheduler: Scheduler):
    freed = scheduler.reap()
    return len(freed)


def run_forever(scheduler: Scheduler, sleep):
    while True:
        run_tick(scheduler)
        sleep(1)

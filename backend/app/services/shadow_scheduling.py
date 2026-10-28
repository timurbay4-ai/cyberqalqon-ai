"""FIFO bounded admission; request-owned work only, no durable-delivery claim."""
import threading
import time
from collections import Counter,deque
from contextlib import contextmanager
from app.db.cqql import CQQLQueryCancelledError


class ShadowAdmissionError(RuntimeError):pass


class ShadowScheduler:
    def __init__(self,*,workers=1,queue_size=4,wait_seconds=.5):
        if not 1<=workers<=2 or not 0<=queue_size<=8 or not 0<wait_seconds<=.5:raise ValueError('invalid shadow budgets')
        self.workers,self.queue_size,self.wait_seconds=workers,queue_size,wait_seconds
        self._condition=threading.Condition();self._queue=deque();self._active=0;self._closed=False
        self._counts=Counter();self._wait_ms=0.

    @contextmanager
    def admit(self,cancel_event=None):
        ticket=object();began=time.perf_counter()
        with self._condition:
            if self._closed:raise ShadowAdmissionError('SHADOW_SHUTDOWN')
            if (self._active>=self.workers or self._queue) and len(self._queue)>=self.queue_size:
                self._counts['rejected']+=1;raise ShadowAdmissionError('SHADOW_QUEUE_FULL')
            self._queue.append(ticket)
            waiting=len(self._queue)-int(self._active<self.workers)
            self._counts['queue_peak']=max(self._counts['queue_peak'],waiting)
            try:
                while self._queue[0] is not ticket or self._active>=self.workers:
                    if cancel_event is not None and cancel_event.is_set():raise CQQLQueryCancelledError('Shadow wait cancelled')
                    if self._closed:raise ShadowAdmissionError('SHADOW_SHUTDOWN')
                    if time.perf_counter()-began>=self.wait_seconds:
                        self._counts['expired']+=1;raise ShadowAdmissionError('SHADOW_QUEUE_EXPIRED')
                    self._condition.wait(.01)
                if cancel_event is not None and cancel_event.is_set():raise CQQLQueryCancelledError('Shadow wait cancelled')
                self._queue.popleft();self._active+=1;self._counts['admitted']+=1
                self._wait_ms+=(time.perf_counter()-began)*1000
            except BaseException:
                if ticket in self._queue:self._queue.remove(ticket)
                self._condition.notify_all();raise
        try:yield
        finally:
            with self._condition:
                self._active-=1;self._counts['released']+=1;self._condition.notify_all()

    def snapshot(self):
        with self._condition:return {'inflight':self._active,'queue_depth':len(self._queue),
            'workers':self.workers,'queue_capacity':self.queue_size,'wait_ms_total':round(self._wait_ms,3),**self._counts}

    def close(self):
        with self._condition:self._closed=True;self._condition.notify_all()

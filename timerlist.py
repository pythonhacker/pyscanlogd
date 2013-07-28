# -- coding: utf-8
import time

class TimerList(list):
    """ List class of fixed size with entries that time out automatically """

    def __getattribute__(self, name):
        if name in ('insert','pop','extend'):
            raise NotImplementedError
        else:
            return super(TimerList, self).__getattribute__(name)
        
    def __init__(self, maxsz, ttl):
        # Maximum size
        self.maxsz = maxsz
        # Time to live for every entry
        self.ttl = ttl

    def append(self, item):
        """ Append an item to end """

        if len(self)<self.maxsz:
            # We append the time-stamp with the item
            super(TimerList, self).append((time.time(), item))
        else:
            n=self.collect()
            if n:
                # Some items removed, so append
                super(TimerList, self).append((time.time(), item))
            else:
                raise ValueError,'could not append item'
            
    def collect(self):
        """ Collect and remove aged items """
        
        t=time.time()
        old = []
        for item in self:
            if (t-item[0])>self.ttl:
                old.append(item)

        
        for item in old:
            self.remove(item)

        return len(old)

    # Access functions
    def __getitem__(self, index):
        item = super(TimerList, self).__getitem__(index)
        if type(index) is slice:
            return [i[1] for i in item]
        else:
            return item[1]
        
    def __setitem__(self,  index, item):
        # Allow only tuples with time-stamps >= current time-stamp as 1st member
        if type(item) == tuple and len(item) == 2  and type(item[0]) == float and item[0]>=time.time():
            super(TimerList, self).__setitem__(index, item)
        else:
            raise TypeError, 'invalid entry'

    def __contains__(self, item):

        items = [rest for (tstamp,rest) in self]
        return item in items

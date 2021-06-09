from pipeproxy import proxy
from multiprocessing import Process
import time


class Example:
    def __init__(self):
        self.parameter = None

    def setParameter(self, parameter):
        print( "setting parameter to: " + str(parameter))
        self.parameter = parameter

    def getParameter(self):
        print ("getting parameter: " + str(self.parameter))
        return self.parameter


def setParameterTest(exampleLookAlike):
    exampleLookAlike.append(1)


def getParameterTest(exampleLookAlike):
    return exampleLookAlike.getParameter() == 1


example = Example()
# example = list()
exampleProxy, exampleProxyListener = proxy.createProxy(example)


# TEST 1
# p = Process(target=setParameterTest, args=(exampleProxy,))
# p.start()
# time.sleep(1)
# exampleProxyListener.listen()
# assert example[0] == 1

#TEST 2
p = Process(target=getParameterTest, args=(exampleProxy,))
p.start()
example.setParameter(1)
while exampleProxyListener.listen():
    pass
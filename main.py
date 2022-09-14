from Tools.winscp import WinSCP
from Tools.mobaxterm import MobaXTerm
from Tools.mongo import Robomongo


if __name__ == '__main__':
    winobj = WinSCP()
    winobj.run()

    robo = Robomongo()
    robo.run()

    mobaxterm = MobaXTerm()
    mobaxterm.run()


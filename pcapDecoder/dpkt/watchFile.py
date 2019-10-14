import os, threading
from watchdog.observers import Observer
from watchdog.events import *
from watchdog.utils.dirsnapshot import DirectorySnapshot, DirectorySnapshotDiff
import pickle
import datetime

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, aim_path):
        FileSystemEventHandler.__init__(self)
        self.aim_path = aim_path
        self.timer = None
        self.snapshot = DirectorySnapshot(self.aim_path)

        obj=pickle.dumps(self.snapshot)
        with open("snapshot.obj","wb")as f:
            f.write(obj)
    
    def on_any_event(self, event):
        if self.timer:
            self.timer.cancel()
        
        self.timer = threading.Timer(2000, self.checkSnapshot)
        self.timer.start()
    
    def checkSnapshot(self):
        snapshot = DirectorySnapshot(self.aim_path)
        diff = DirectorySnapshotDiff(self.snapshot, snapshot)
        self.snapshot = snapshot
        self.timer = None
        
        print("files_created:", diff.files_created)
        print("files_deleted:", diff.files_deleted)
        print("files_modified:", diff.files_modified)
        print("files_moved:", diff.files_moved)
        print("dirs_modified:", diff.dirs_modified)
        print("dirs_moved:", diff.dirs_moved)
        print("dirs_deleted:", diff.dirs_deleted)
        print("dirs_created:", diff.dirs_created)
        
        # 接下来就是你想干的啥就干点啥，或者该干点啥就干点啥
        pass
    
class DirMonitor(object):
    """文件夹监视类"""
    
    def __init__(self, aim_path):
        """构造函数"""
        
        self.aim_path= aim_path
        self.observer = Observer()
    
    def start(self):
        """启动"""
        
        event_handler = FileEventHandler(self.aim_path)
        self.observer.schedule(event_handler, self.aim_path, True)
        self.observer.start()
    
    def stop(self):
        """停止"""
        
        self.observer.stop()
    
if __name__ == "__main__":

    '''folderList = os.listdir("/home/zte/data/erde/googleFreeTrans/pcapFile/2019/pcap_443b/")
    fileList  = []
    for folder in folderList:
        fileList = fileList + os.listdir("/home/zte/data/erde/googleFreeTrans/pcapFile/2019/pcap_443b/"+folder)
    obj=pickle.dumps(fileList)
    with open("snapshot2.obj","wb")as f:
        f.write(obj)'''


    '''fileList  = []
    obj=pickle.dumps(fileList)
    with open("snapshot3.obj","wb")as f:
        f.write(obj)

    with open("snapshot3.obj","rb")as f:
        a = set(pickle.load(f))
        print(a)'''

    #monitor = DirMonitor("/home/zte/data/erde/googleFreeTrans/pcapFile/2019/pcap_443b/Custom_00_20190704113328_0000_finish")
    #monitor.start()

    delta = datetime.timedelta(days = 1)
    seconds = delta.total_seconds()
    print(seconds)

    with open("snapshot3.obj","rb")as f:
        a = set(pickle.load(f))
        print(a)

    with open("snapshot1.obj","rb")as f:
        b = set(pickle.load(f))

    print(b-a)
    #print(set(b).difference(set(b)))
    #print(set(a).intersection(set(b)))



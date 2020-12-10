from watchdog.observers import Observer
from watchdog.events import *
from typing import List
import os

from filters.meta import BaseFilter
from engines.meta import Engine
from filters import BaseFilter

class FileWatcher:
  '''文件系统变化监听器'''
  def __init__(self, paths: List[str]):
    self.filters = []
    self.paths = paths
  
  def register_filter(self, filter: BaseFilter):
    self.filters.append(filter)
    logging.debug(str(filter) + "注册成功")

  def judge(self, path):
    for filter in self.filters:
      filter: BaseFilter
      filter.judge(Engine.FILE, { 'path': path })

  def start(self):
    class Handler(FileSystemEventHandler):
      def __init__(self):
        FileSystemEventHandler.__init__(self)
      def on_created(_, event: FileCreatedEvent): # 当文件创建时做出操作
        if not event.is_directory:
          self.judge(os.path.abspath(event.src_path)) # 对文件的绝对路径做检测
      def on_modified(_, event: FileModifiedEvent): # 当文件修改时做出操作
        if not event.is_directory:
          self.judge(os.path.abspath(event.src_path))
    self.observer = Observer()
    handler = Handler()
    for path in self.paths:
      self.observer.schedule(handler, path, True) # 注册 watchdog observer 处理器
    self.observer.start()
    logging.info('FileWatcher 启动完成')
  
  def join(self):
    self.observer.join()

  def stop(self):
    self.observer.stop()

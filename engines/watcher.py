from watchdog.observers import Observer
from watchdog.events import *
from typing import List

from filters.meta import BaseFilter
from engines.meta import Engine
from filters import BaseFilter

class FileWatcher:
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
      def on_created(_, event: FileCreatedEvent):
        if not event.is_directory:
          self.judge(event.src_path)
      def on_modified(_, event: FileModifiedEvent):
        if not event.is_directory:
          self.judge(event.src_path)
    self.observer = Observer()
    handler = Handler()
    for path in self.paths:
      self.observer.schedule(handler, path, True)
    self.observer.start()
  
  def join(self):
    self.observer.join()

  def stop(self):
    self.observer.stop()

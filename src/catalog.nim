## catalog.nim - assembles every check module into one registry.

import core
import checks/system
import checks/files
import checks/services
import checks/network
import checks/kernel

proc buildRegistry*(): Registry =
  result = Registry()
  system.register(result)
  files.register(result)
  services.register(result)
  network.register(result)
  kernel.register(result)

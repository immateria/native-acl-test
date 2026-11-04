require "uuid"
require "./errors"
require "./internal/binary"
require "./windows/sid"
require "./windows/ace"
require "./windows/list"
require "./windows/descriptor"
require "./windows/snapshot"
require "./windows/update"

{% if flag?(:win32) %}
  require "./platform/windows/lib_security"
  require "./platform/windows/backend"
{% end %}

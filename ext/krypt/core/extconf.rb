=begin

= Info

krypt-core API - C version

Copyright (C) 2011
Hiroshi Nakamura <nahi@ruby-lang.org>
Martin Bosslet <martin.bosslet@googlemail.com>
All rights reserved.

= License
This program is distributed under the same license as Ruby.
See the file 'LICENSE' for further details.

=end

require 'mkmf'

dir_config('profiler')

message "=== krypt-core API - C version ===\n"

arg = ARGV.shift
if arg
  if arg.include? "-g"
    debug = true
  elsif arg.include? "-p"
    profiler = true
    unless have_library("profiler", "ProfilerStart")
      message "'libprofiler' could not be found.\n"
      exit 1
    end 
  end
end

if CONFIG['GCC'] == 'yes'
  if debug
    flags = "--coverage -g3 -fprofile-arcs -ftest-coverage"
    message "!! set #{flags} for coverage !!"
    $CFLAGS += " #{flags}"
    $DLDFLAGS += " #{flags}"
    $LIBS += " -lgcov"
  end
  if profiler
    message "Linking to profiler library\n"
    pkg_config('profiler')
    $LIBS += " -lprofiler"
  end
end

message "=== Checking Ruby features ===\n"

have_header("ruby/io.h")
have_func("rb_big_pack")
have_func("rb_enumeratorize")
have_func("rb_str_encode")

message "=== Checking platform features ===\n"

have_func("gmtime_r")

create_header
create_makefile("kryptcore")
message "Done.\n"

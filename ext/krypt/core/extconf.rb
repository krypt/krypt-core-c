=begin

= Info

krypt-core API - C implementation

Copyright (C) 2011-2013
Hiroshi Nakamura <nahi@ruby-lang.org>
Martin Bosslet <martin.bosslet@gmail.com>
All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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

#!/bin/bash
echo "starting inotify listener on $(pwd)"
# feed the inotify events into a while loop that creates
# the variables 'date' 'time' 'dir' 'file' and 'event'
inotifywait -mr --timefmt '%d/%m/%y %H:%M' --format '%T %w %f %e' \
-e modify $(pwd) \
| while read date time dir file event
do
    if [[ "$file" =~ \.go$ && "$dir" =~ "$(pwd)" ]]; then
        echo --- $date $time ---
	    make install && make test
        echo
    fi
done

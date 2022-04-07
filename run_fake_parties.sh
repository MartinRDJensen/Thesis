osascript -e 'tell app "Terminal"
    do script "z MP && ./fake-spdz-rsig-party.x -p 1"
end tell'
osascript -e 'tell app "Terminal"
    do script "z MP && ./fake-spdz-rsig-party.x -p 0"
end tell'

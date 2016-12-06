rmdir /q /s build
md build
cd build
cmake -G "Visual Studio 14 Win64" ..

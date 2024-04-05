@echo off
setlocal

if not exist "build/vs" md "build/vs"
cd "build/vs"
cmake -G "Visual Studio 17 2022" -A x64 -S "../.." -DCZSPAS_Tests=ON -DCZSPAS_Samples=ON


REM echo off
REM setlocal enabledelayedexpansion
REM set @arg1=%1
REM for /f "delims==" %%A in (input.txt) do set string=%%A & echo !string: =    ! >> output.txt
REM ECHO %@arg1%

@echo off
setlocal enabledelayedexpansion
for /f "tokens=*" %%a in (input.txt) do (
  set line=%%a
  set _test=!line:~0,17!
  set _test=%_test:09469=00000%

  REM echo !chars! --- !line!
)
 ECHO  !_test!
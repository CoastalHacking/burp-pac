#!/bin/sh

java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=8000 -jar -Xmx2g burpsuite_free_v1.7.27.jar 

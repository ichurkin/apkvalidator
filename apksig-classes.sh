#!/usr/bin/env sh

find ./apksig/src/main -name "*.java" -type f | sed 's#\.java#\.class, !@#g' | sed 's#\./apksig/src/main/java/##g' | sed 's#/#\.#g' | sed 's#!@#//#g' > classes.txt

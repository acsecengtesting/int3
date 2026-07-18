#!/bin/bash
# Build a test jar containing com.example.HelloPlugin
set -e
cd /root/jclass_monitor

mkdir -p testlib_build/com/example

cat > testlib_build/com/example/HelloPlugin.java << 'EOF'
package com.example;

public class HelloPlugin {
    public String getName() {
        return "HelloPlugin";
    }

    public void run() {
        System.out.println("HelloPlugin loaded and running!");
    }
}
EOF

javac -d testlib_build testlib_build/com/example/HelloPlugin.java
jar cf testplugin.jar -C testlib_build com/
echo "Built testplugin.jar"
jar tf testplugin.jar

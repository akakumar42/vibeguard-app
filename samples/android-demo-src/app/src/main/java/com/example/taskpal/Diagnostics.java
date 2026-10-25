package com.example.taskpal;

import java.io.IOException;

/** "Check connection" button on the help screen. */
public class Diagnostics {

    public boolean canReachServer(String host) throws IOException, InterruptedException {
        Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
        return p.waitFor() == 0;
    }
}

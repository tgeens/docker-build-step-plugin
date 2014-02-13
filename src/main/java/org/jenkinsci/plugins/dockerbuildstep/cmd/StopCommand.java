package org.jenkinsci.plugins.dockerbuildstep.cmd;

import java.util.Arrays;
import java.util.List;

import hudson.Extension;

import org.kohsuke.stapler.DataBoundConstructor;

import com.kpelykh.docker.client.DockerClient;
import com.kpelykh.docker.client.DockerException;

public class StopCommand extends DockerCommand {

    private String containerIds;

    @DataBoundConstructor
    public StopCommand(String containerIds) {
        this.containerIds = containerIds;
    }

    public String getContainerIds() {
        return containerIds;
    }

    @Override
    public void execute() throws DockerException {
        if (containerIds == null || containerIds.isEmpty()) {
            throw new IllegalArgumentException("At least one parameter is required");
        }
        
        List<String> ids = Arrays.asList(containerIds.split(","));
        DockerClient client = getClient();
        for(String id : ids) {
            id = id.trim();
            client.stopContainer(id);
        }
    }

    @Extension
    public static class StopCommandDescriptor extends DockerCommandDescriptor {
        @Override
        public String getDisplayName() {
            return "Stop constainer(s)";
        }
    }

}
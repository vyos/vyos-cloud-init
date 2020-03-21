// Copyright (C) 2019 VyOS maintainers and contributors
//
// This program is free software; you can redistribute it and/or modify
// in order to easy exprort images built to "external" world
// it under the terms of the GNU General Public License version 2 or later as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

@NonCPS

def getGitBranchName() {
    def branch = scm.branches[0].name
    return branch.split('/')[-1]
}

def getGitRepoURL() {
    return scm.userRemoteConfigs[0].url
}

def getGitRepoName() {
    return getGitRepoURL().split('/').last()
}

// Returns true if this is a custom build launched on any project fork.
// Returns false if this is build from git@github.com:vyos/<reponame>.
// <reponame> can be e.g. vyos-1x.git or vyatta-op.git
def isCustomBuild() {
    // GitHub organisation base URL
    def gitURI = 'git@github.com:vyos/' + getGitRepoName()
    def httpURI = 'https://github.com/vyos/' + getGitRepoName()

    return !((getGitRepoURL() == gitURI) || (getGitRepoURL() == httpURI)) || env.CHANGE_ID
}

def setDescription() {
    def item = Jenkins.instance.getItemByFullName(env.JOB_NAME)

    // build up the main description text
    def description = ""
    description += "<h2>VyOS individual package build: " + getGitRepoName().replace('.git', '') + "</h2>"

    if (isCustomBuild()) {
        description += "<p style='border: 3px dashed red; width: 50%;'>"
        description += "<b>Build not started from official Git repository!</b><br>"
        description += "<br>"
        description += "Repository: <font face = 'courier'>" + getGitRepoURL() + "</font><br>"
        description += "Branch: <font face = 'courier'>" + getGitBranchName() + "</font><br>"
        description += "</p>"
    } else {
        description += "Sources taken from Git branch: <font face = 'courier'>" + getGitBranchName() + "</font><br>"
    }

    item.setDescription(description)
    item.save()
}

/* Only keep the 10 most recent builds. */
def projectProperties = [
    [$class: 'BuildDiscarderProperty',strategy: [$class: 'LogRotator', numToKeepStr: '10']],
]

properties(projectProperties)
setDescription()

node('Docker') {
    stage('Define Agent') {
        script {
            // create container name on demand
            def branchName = getGitBranchName()
            // Adjust PR target branch name so we can re-map it to the proper
            // Docker image. CHANGE_ID is set only for pull requests, so it is
            // safe to access the pullRequest global variable
            if (env.CHANGE_ID) {
                branchName = "${env.CHANGE_TARGET}".toLowerCase()
            }
            if (branchName.equals("master")) {
                branchName = "current"
            }
            env.DOCKER_IMAGE = "vyos/vyos-build:" + branchName
        }
    }
}

pipeline {
    agent {
        docker {
            args "--sysctl net.ipv6.conf.lo.disable_ipv6=0 -e GOSU_UID=1006 -e GOSU_GID=1006"
            image "${env.DOCKER_IMAGE}"
            alwaysPull true
        }
    }
    options {
        disableConcurrentBuilds()
        timeout(time: 30, unit: 'MINUTES')
        timestamps()
    }
    stages {
        stage('Fetch') {
            steps {
                script {
                    dir('build') {
                        checkout scm
                    }
                }
            }
        }
        stage('Build') {
            steps {
                script {
                    dir('build') {
                        def commitId = sh(returnStdout: true, script: 'git rev-parse --short=11 HEAD').trim()
                        currentBuild.description = sprintf('Git SHA1: %s', commitId[-11..-1])
                        sh 'ls -al'
                        sh './packages/bddeb'
                    }
                }
            }
        }
    }
    post {
        cleanup {
            deleteDir()
        }
        success {
            script {
                dir('build') {
                    // archive *.deb artifact on custom builds, deploy to repo otherwise
                    if ( isCustomBuild()) {
                        archiveArtifacts artifacts: 'cloud-init_*_all.deb', fingerprint: true
                    } else {
                        // publish build result, using SSH-dev.packages.vyos.net Jenkins Credentials
                        sshagent(['SSH-dev.packages.vyos.net']) {
                            // build up some fancy groovy variables so we do not need to write/copy
                            // every option over and over again!
                            def RELEASE = getGitBranchName()
                            if (getGitBranchName() == "master") {
                                RELEASE = 'current'
                            }

                            def VYOS_REPO_PATH = '/home/sentrium/web/dev.packages.vyos.net/public_html/repositories/' + RELEASE + '/'
                            if (getGitBranchName() == "crux")
                                VYOS_REPO_PATH += 'vyos/'

                            def SSH_OPTS = '-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=ERROR'
                            def SSH_REMOTE = 'khagen@10.217.48.113'

                            echo "Uploading package(s) and updating package(s) in the repository ..."

                            files = findFiles(glob: 'cloud-init_*_all.deb')
                            files.each { PACKAGE ->
                                def ARCH = sh(returnStdout: true, script: "dpkg-deb -f ${PACKAGE} Architecture").trim()
                                def SUBSTRING = sh(returnStdout: true, script: "dpkg-deb -f ${PACKAGE} Package").trim()
                                def SSH_DIR = '~/VyOS/' + RELEASE + '/' + ARCH
                                def ARCH_OPT = ''
                                if (ARCH != 'all')
                                    ARCH_OPT = '-A ' + ARCH

                                // No need to explicitly check the return code. The pipeline
                                // will fail if sh returns a non 0 exit code
                                sh """
                                    ssh ${SSH_OPTS} ${SSH_REMOTE} -t "bash --login -c 'mkdir -p ${SSH_DIR}'"
                                """
                                sh """
                                    scp ${SSH_OPTS} ${PACKAGE} ${SSH_REMOTE}:${SSH_DIR}/
                                """
                                sh """
                                    ssh ${SSH_OPTS} ${SSH_REMOTE} -t "uncron-add 'reprepro -v -b ${VYOS_REPO_PATH} ${ARCH_OPT} remove ${RELEASE} ${SUBSTRING}'"
                                """
                                sh """
                                    ssh ${SSH_OPTS} ${SSH_REMOTE} -t "uncron-add 'reprepro -v -b ${VYOS_REPO_PATH} deleteunreferenced'"
                                """
                                sh """
                                    ssh ${SSH_OPTS} ${SSH_REMOTE} -t "uncron-add 'reprepro -v -b ${VYOS_REPO_PATH} ${ARCH_OPT} includedeb ${RELEASE} ${SSH_DIR}/${PACKAGE}'"
                                """
                            }
                        }
                    }
                }
            }
        }
    }
}


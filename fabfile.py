from fabric.api import *
import requests

project = "kenmare"
repository = "git@github.com:Bowery/" + project + ".git"
hosts = [
  'ubuntu@ec2-54-166-150-115.compute-1.amazonaws.com',
  'ubuntu@ec2-54-162-40-78.compute-1.amazonaws.com'
]
env.key_filename = '/home/ubuntu/.ssh/id_aws'
env.password = 'java$cript'

@parallel
def restart():
  sudo('mkdir -p /home/ubuntu/gocode/src/github.com/Bowery/')
  with cd('/home/ubuntu/gocode/src/github.com/Bowery/gopackages'):
    run('git pull')

  with cd('/home/ubuntu/gocode/src/github.com/Bowery/delancey'):
    run('git pull')
    
  with cd('/home/ubuntu/gocode/src/github.com/Bowery/' + project):
    run('git pull')
    sudo('GOPATH=/home/ubuntu/gocode go get -d')
    sudo('GOPATH=/home/ubuntu/gocode go build -o kenmare-server')

    sudo('cp -f ' + project + '.conf /etc/init/' + project + '.conf')
    sudo('initctl reload-configuration')
    sudo('restart ' + project)

def deploy():
  execute(restart, hosts=hosts)

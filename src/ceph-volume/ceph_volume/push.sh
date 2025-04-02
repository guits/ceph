git add -u
git commit -v -s --amend -m "devel/wip"
git push -f fork cv-refactor-osd-objectstore
ssh -t ceph-dev "sudo bash -x /root/ceph/src/ceph-volume/pull-and-build.sh $*"

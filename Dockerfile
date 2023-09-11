FROM openeuler/openeuler:22.03-lts@sha256:a56d8e3b7049914a6a314100802fd356c4922d6f6ba62c476a91bcd774e831c3

RUN yum update -y && yum install -y \
    git \
    java-17-openjdk \
    && rm -rf /var/cache/yum

WORKDIR /opt
RUN git clone --recurse-submodules https://github.com/opensourceways/uvp.git -b BRANCH
WORKDIR /opt/uvp
RUN /bin/bash gradlew bootWar

ENTRYPOINT ["/bin/bash", "/opt/uvp/docker-entrypoint.sh"]

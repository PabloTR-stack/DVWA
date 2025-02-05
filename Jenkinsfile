#!groovy

import groovy.json.JsonSlurper
import java.text.SimpleDateFormat
import java.time.LocalDateTime

pipeline {
  agent { 
    kubernetes {
       yaml '''
    apiVersion: v1
    kind: Pod
    metadata:
        name: jenkins-pl-pod
        labels:
            app: jenkins-pl-pod
    spec:
        containers:
        - name: docker
          image: showcasepreprodacr.azurecr.io/docker:27.5.2-dind@sha256:3fea59d9ba248f52f0210259cc4c0849d99bce0824345b8945247d964fac9c6c
          securityContext:
            privileged: true
          ports:
          - name: dvwa
            containerPort: 4280
          - name: sock
            containerPort: 2376
        - name: dc
          image: showcasepreprodacr.azurecr.io/cached_dc:latest
          command: ["sleep"]
          args: ["infinity"]
        - name: jnlp
          image: jenkins/inbound-agent:latest
        - name: zap
          image: ghcr.io/zaproxy/zaproxy:stable
          env:
            - name: API_KEY
              valueFrom:
                secretKeyRef:
                  name: zap
                  key: apikey
          command: ["/bin/sh", "-c", "zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=${API_KEY} -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true"]
          ports:
          - name: http
            containerPort: 8080
        '''
        }
    }

    stages { 
        stage('Checkout') {
            steps{
                container('jnlp') {
                    echo 'Downloading DVWA source code...'
                    git url: "https://github.com/PabloTR-stack/DVWA.git"
                }
            }
        }
        stage('SonarQube analysis') {
            steps{
                container('jnlp') {
                    script {
                        scannerHome = tool 'reginleifScanner'// must match the name of an actual scanner installation directory on your Jenkins build agent
                    }
                    withSonarQubeEnv('sq_yggdrasil') {// If you have configured more than one global server connection, you can specify its name as configured in Jenkins
                        nodejs(nodeJSInstallationName: 'jenkinsNodeJS') {
                            withCredentials([string(credentialsId: 'SQ_TOKEN', variable: 'SQ_TOKEN'), string(credentialsId: 'SQ_URL', variable: 'SQ_URL'), string(credentialsId: 'SQU_TOKEN', variable: 'SQU_TOKEN')]) {
                            sh scannerHome + '/bin/sonar-scanner -Dsonar.projectKey=DVWA -Dsonar.sources=./ -Dsonar.host.url=' + SQ_URL + ' -Dsonar.login=' + SQ_TOKEN
                            script{
                                def report = sh(returnStdout: true, script: 'curl -s -u '+SQU_TOKEN+': '+SQ_URL+'/api/hotspots/search?projectKey=DVWA')
                                writeFile (file: "hotspot_report.json", text: report)   
                                }  
                            archiveArtifacts artifacts: 'hotspot_report.json'   
                            }
                        }
                    }
                }
            }
        }
        stage("Quality Gate"){
            steps{
                container('jnlp') {
                    withCredentials([string(credentialsId: 'SQ_TOKEN', variable: 'SQ_TOKEN'), string(credentialsId: 'SQ_URL', variable: 'SQ_URL'), string(credentialsId: 'SQU_TOKEN', variable: 'SQU_TOKEN')]) {
                        script{
                        def qg = sh(returnStdout: true, script: 'curl -s -u '+SQU_TOKEN+': '+SQ_URL+'/api/qualitygates/project_status?projectKey=DVWA')
                        def status = new JsonSlurper().parseText(qg).projectStatus.status
                        for (i = 0 ; status != 'OK' && i < 6 ; i++) {
                            qg = sh(returnStdout: true, script: 'curl -s -u '+SQU_TOKEN+': '+SQ_URL+'/api/qualitygates/project_status?projectKey=DVWA')
                            status = new JsonSlurper().parseText(qg).projectStatus.status
                            sleep 10
                        }
                    // timeout(time: 1, unit: 'MINUTES') { // Just in case something goes wrong, pipeline will be killed after a timeout
                    //         def qg = waitForQualityGate() // Reuse taskId previously collected by withSonarQubeEnv
                    //         if (qg.status != 'OK') {
                    //         error "Pipeline aborted due to quality gate failure: ${qg.status}"
                    //         }
                    //     }
                        }
                    }
                }
            }
        }
        stage('OWASP Dependency-Check Vulnerabilities') {
            steps{
                container('dc') {
                    sh "ls"
                    sh "dependency-check.sh -o \'./\' -s \'./\' -f \'JSON\'"
                    //sh('wget https://github.com/jeremylong/DependencyCheck/releases/download/v12.0.2/dependency-check-12.0.2-release.zip')
                    //sh('ls')
                    // dependencyCheck additionalArguments: ''' 
                    //             -o './'
                    //             -s './'
                    //             -f 'JSON' 
                    //             --prettyPrint''', odcInstallation: 'owasp_dc'
                    
                    // dependencyCheckPublisher pattern: 'dependency-check-report.json'
                    // archiveArtifacts artifacts: 'dependency-check-report.json'
                }
            }
        } 
        stage("Deploy containers"){
            steps{
                container('docker') {
                    sh 'docker compose up -d'
                }
            }
        }
        
        stage("OWASP ZAP analysis"){
            steps{
                container('jnlp') {
                    withCredentials([string(credentialsId: 'ZAP_TOKEN', variable: 'ZAP_TOKEN')]) {
                        script{
                        def zap_url = "http://jenkins-pl-pod-service.reginleif.svc.cluster.local:8080"
                        def target_url = "http://jenkins-pl-pod-service.reginleif.svc.cluster.local:4280"
                        def response = httpRequest zap_url + '/JSON/spider/action/scan/?apikey=' + ZAP_TOKEN + '&url=' + target_url + '&contextName=&recurse='
                        def json = new JsonSlurper().parseText(response.content)
                        println("Scan ID: ${json.scan}")
                        def scan_id = json.scan

                        response = null
                        json = null

                        response = httpRequest zap_url + '/JSON/spider/view/status/?apikey=' + ZAP_TOKEN + '&scanId=' + scan_id
                        json = new JsonSlurper().parseText(response.content)

                        response = null
                        json = null

                        def i = 0
                        while(i < 100){
                            response = httpRequest url: zap_url + '/JSON/spider/view/status/?apikey=' + ZAP_TOKEN + '&scanId=' + scan_id ,quiet:true
                            json = new JsonSlurper().parseText(response.content)
                            if (i != json.status.toInteger()) println("Progress: ${json.status}%")
                            i = json.status.toInteger()
                            response = null
                            json = null
                            sleep 10
                        }

                        

                        response = httpRequest zap_url + '/JSON/spider/view/results/?apikey=' + ZAP_TOKEN + '&scanId=' + scan_id
                        writeFile (file: "spider_results.json", text: response.content)
                    
                    
                        //def spider_results = json
                        response = null
                        json = null

                        response = httpRequest zap_url + '/JSON/ascan/action/scan/?apikey=' + ZAP_TOKEN + '&url=' + target_url + '&recurse=true&inScopeOnly=&scanPolicyName=&method=&postData=&contextId='
                        json = new JsonSlurper().parseText(response.content)
                        println("Active scan id: ${json.scan}") 
                        
                        scan_id = json.scan
                        response = null
                        json = null
                        
                        response = httpRequest zap_url + '/JSON/ascan/view/status/?apikey=' + ZAP_TOKEN + '&scanId=' + scan_id
                        json = new JsonSlurper().parseText(response.content)

                        response = null
                        json = null
                        i = 0
                        while(i < 100){
                            response = httpRequest url: zap_url + '/JSON/ascan/view/status/?apikey=' + ZAP_TOKEN + '&scanId=' + scan_id ,quiet:true
                            json = new JsonSlurper().parseText(response.content)
                            if (i != json.status.toInteger()) println("Progress: ${json.status}%")
                            i = json.status.toInteger()
                            response = null
                            json = null
                            sleep 10
                        }

                        response = httpRequest zap_url + '/XML/core/view/alerts/?apikey=' + ZAP_TOKEN + '&baseurl=' + target_url + '&start=0&count=10'
                        writeFile (file: "alerts.xml", text: response.content)
                    }
                    archiveArtifacts artifacts: 'alerts.xml'
                    archiveArtifacts artifacts: 'spider_results.json'
                    }
                }
            }
        }
        stage('DefectDojoPublisher') {
            steps{
                container('jnlp') {
                    withCredentials([string(credentialsId: 'defectDojoAPIKEY', variable: 'API_KEY')]) {
                        script{
                            def date = new Date()
                            def sdf = new SimpleDateFormat("yyyy-MM-dd")
                            def product_id = 95
                            def end_date = sdf.format(date)
                            def dd_URL = "http://defectdojo-django.s-dm.svc.cluster.local:80"

                            //crear engagement para el dia de hoy
                            def engagement_j = "{\"tags\":[\"TEST\"],\"name\": \"SAST/SCA/DAST reports from ${LocalDateTime.now()}\",\"description\": \"Reports from SonarQube, OWASP DC and OWASP ZAP respectively\",\"target_start\":\"$end_date\",\"product\":$product_id,\"target_end\":\"$end_date\",\"engagement_type\":\"CI/CD\"}"
                            def engagement_r = sh(returnStdout: true, script:  """curl -o - -X POST \
                            -H 'content-type: application/json' \
                            -H 'Authorization: Token $API_KEY' \
                            -d '$engagement_j' \
                            $dd_URL/api/v2/engagements/""")

                            //subir los artefactos del pipeline
                            def engagement_id = new JsonSlurper().parseText(engagement_r).id

                            // Análisis ZAP 
                            def zap_r = sh(returnStdout: true, script:  """curl -o - -X POST \
                            -H 'accept: application/json' \
                            -H 'Content-Type: multipart/form-data' \
                            -H 'Authorization: Token """+API_KEY+"""' \
                            -F 'engagement=$engagement_id' \
                            -F 'scan_date=$end_date' \
                            -F 'engagement_end_date=$end_date' \
                            -F 'product_name=DVWA' \
                            -F 'file=@alerts.xml;type=application/xml' \
                            -F 'scan_type=ZAP Scan' \
                            $dd_URL/api/v2/import-scan/""")

                            //Análisis SQ
                            def sq_r = sh(returnStdout: true, script:  """curl -o - -X POST \
                            -H 'accept: application/json' \
                            -H 'Content-Type: multipart/form-data' \
                            -H 'Authorization: Token """+API_KEY+"""' \
                            -F 'engagement=$engagement_id' \
                            -F 'scan_date=$end_date' \
                            -F 'engagement_end_date=$end_date' \
                            -F 'product_name=DVWA' \
                            -F 'file=@hotspot_report.json;type=application/json' \
                            -F 'scan_type=SonarQube Scan' \
                            $dd_URL/api/v2/import-scan/""")

                            //Análisis DC
                            // def dc_r = sh(returnStdout: true, script:  """curl -o - -X POST \
                            // -H 'accept: application/json' \
                            // -H 'Content-Type: multipart/form-data' \
                            // -H 'Authorization: Token """+API_KEY+"""' \
                            // -F 'engagement=$engagement_id' \
                            // -F 'scan_date=$end_date' \
                            // -F 'engagement_end_date=$end_date' \
                            // -F 'product_name=DVWA' \
                            // -F 'file=@dependency-check-report.json;type=application/json' \
                            // -F 'scan_type=Dependency Check Scan' \
                            // $dd_URL/api/v2/import-scan/""")
                        }
                    }
                }
            }
        }
    }
}
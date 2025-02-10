#!groovy

import groovy.json.JsonSlurperClassic
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
                        def status = new JsonSlurperClassic().parseText(qg).projectStatus.status
                        for (i = 0 ; status != 'OK' && i < 6 ; i++) {
                            qg = sh(returnStdout: true, script: 'curl -s -u '+SQU_TOKEN+': '+SQ_URL+'/api/qualitygates/project_status?projectKey=DVWA')
                            status = new JsonSlurperClassic().parseText(qg).projectStatus.status
                            sleep 10
                            }
                        }
                    }
                }
            }
        }
        stage('OWASP Dependency-Check Vulnerabilities') {
            steps{
                container('dc') {
                    //sh 'rm -rf test'
                    sh 'npm install'
                    sh 'npm install --package-lock'
                    sh 'touch dc.log'
                    sh "tail -f dc.log | dependency-check.sh \
                        -o ${WORKSPACE} \
                        -s './' \
                        -f 'XML' \
                        -l 'dc.log' \
                        --noupdate \
                        --enableExperimental \
                        --exclude **/*.zip"      
                    archiveArtifacts artifacts: 'dependency-check-report.xml'
                }
            }
        } 
        stage("Deploy containers"){
            steps{
                container('docker') {
                    sh 'docker build -f Dockerfile -t jshop .'
                    sh 'docker run -d -p 3000:3000 jshop'
                    //sh 'docker run --rm -d -p 3000:3000 bkimminich/juice-shop'
                    //sh 'docker ps'
                }
            }
        }
        
        stage("OWASP ZAP analysis"){
            steps{
                container('jnlp') {
                    withCredentials([string(credentialsId: 'ZAP_TOKEN', variable: 'ZAP_TOKEN')]) {
                        script{
                        //define URLs
                        def zap_url = "http://jenkins-pl-pod-service.reginleif.svc.cluster.local:8080"
                        def target_url = "http://jenkins-pl-pod-service.reginleif.svc.cluster.local:3000"
                        //start passive scan
                        def spider_r = httpRequest zap_url + '/JSON/spider/action/scan/?apikey=' + ZAP_TOKEN + '&url=' + target_url + '&contextName=&recurse='
                        def scan_id = new JsonSlurperClassic().parseText(spider_r.content).scan
                        //wait for the passive scan to finish
                        def status_r,status_j
                        def i = 0
                        while(i < 100){
                            status_r = null
                            status_j = null
                            status_r = httpRequest url: zap_url + '/JSON/spider/view/status/?apikey=' + ZAP_TOKEN + '&scanId=' + scan_id ,quiet:true
                            status_j = new JsonSlurperClassic().parseText(status_r.content)
                            if (i != status_j.status.toInteger()) println("Progress: ${status_j.status}%")
                            i = status_j.status.toInteger()
                            //sleep 10
                        }   

                        //response = httpRequest zap_url + '/JSON/spider/view/results/?apikey=' + ZAP_TOKEN + '&scanId=' + scan_id
                        //writeFile (file: "spider_results.json", text: response.content)

                        //start the active scan
                        ascan_r = httpRequest zap_url + '/JSON/ascan/action/scan/?apikey=' + ZAP_TOKEN + '&url=' + target_url + '&recurse=true&inScopeOnly=&scanPolicyName=&method=&postData=&contextId='
                        scan_id = null
                        scan_id = new JsonSlurperClassic().parseText(ascan_r.content).scan
                        //wait for the active scan to finish
                        i = 0
                        while(i < 100){
                            status_r = null
                            status_j = null
                            status_r = httpRequest url: zap_url + '/JSON/ascan/view/status/?apikey=' + ZAP_TOKEN + '&scanId=' + scan_id ,quiet:true
                            status_j = new JsonSlurperClassic().parseText(status_r.content)
                            if (i != status_j.status.toInteger()) println("Progress: ${status_j.status}%")
                            i = status_j.status.toInteger()
                            sleep 10
                        }
                        //get the active scan results
                        def results_r = httpRequest zap_url + '/XML/core/view/alerts/?apikey=' + ZAP_TOKEN + '&baseurl=' + target_url + '&start=0&count=10'
                        writeFile (file: "alerts.xml", text: results_r.content)

                        def reports_r = sh(returnStdout: true, script:  """curl -o - -X GET \
                            -H 'accept: application/xml' \
                            -H 'X-ZAP-API-Key: """+ZAP_TOKEN+"""' \
                            -F 'title=Juice Shop' \
                            -F 'scan_date=$end_date' \
                            -F 'template=traditional-json' \
                            -F 'sites=$target_url' \
                            -F 'reportFileName=jsonreport' \
                            $zap_url/JSON/reports/action/generate/""")
                            echo reports_r
                    }
                    archiveArtifacts artifacts: 'alerts.xml'
                    //archiveArtifacts artifacts: 'spider_results.json'
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
                            def engagement_id = new JsonSlurperClassic().parseText(engagement_r).id

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
                            def dc_r = sh(returnStdout: true, script:  """curl -o - -X POST \
                            -H 'accept: application/json' \
                            -H 'Content-Type: multipart/form-data' \
                            -H 'Authorization: Token """+API_KEY+"""' \
                            -F 'engagement=$engagement_id' \
                            -F 'scan_date=$end_date' \
                            -F 'engagement_end_date=$end_date' \
                            -F 'product_name=DVWA' \
                            -F 'file=@dependency-check-report.xml;type=application/xml' \
                            -F 'scan_type=Dependency Check Scan' \
                            $dd_URL/api/v2/import-scan/""")
                        }
                    }
                }
            }
        }
    }
}
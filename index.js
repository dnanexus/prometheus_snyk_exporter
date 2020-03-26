const _ = require('lodash');
const express = require('express');
const prometheusClient = require('prom-client');
const axios = require('axios');
// const nock = require('nock');
// nock.recorder.rec();

const metricsServer = express();

const DEBUG = process.env['SNYK_EXPORTER_DEBUG'] || false;

const POST_DATA = {
  'filters': {
    'severity': [
      'high',
      'medium',
      'low'
    ],
    'types': [
      'vuln',
      'license'
    ],
    'ignored': false,
    'patched': false
  }
};

var BASE_URL;
var ORG_NAME;
var SNYK_API_TOKEN;
var POLL_TIME_SECONDS;
var httpClient;

const up = new prometheusClient.Gauge({name: 'up', help: 'UP Status'});

const vulnerabilitiesBySeverity = new prometheusClient.Gauge({
  name: 'snyk_num_vulnerabilities_by_severity',
  help: 'Number of Snyk vulnerabilities by severity',
  labelNames: ['project', 'path', 'severity']
});

const vulnerabilitiesByType = new prometheusClient.Gauge({
  name: 'snyk_num_vulnerabilities_by_type',
  help: 'Number of Snyk vulnerabilities by type',
  labelNames: ['project', 'path', 'type']
});

if (require.main === module) {
  const options = {};

  options.SNYK_API_TOKEN = process.env.SNYK_API_TOKEN;
  options.ORG_NAME = process.env.SNYK_ORG_NAME;
  options.BASE_URL = process.env.SNYK_API_BASE_URL;
  options.POLL_TIME_SECONDS = process.env.POLL_TIME_SECONDS;

  init(options);
  startServer();
}

function init (options) {
  if (!options.SNYK_API_TOKEN) {
    throw new Error('Environment variable SNYK_API_TOKEN must be set');
  }
  if (!options.ORG_NAME) {
    throw new Error('Environment variable SNYK_ORG_NAME must be set');
  }
  POLL_TIME_SECONDS = options.POLL_TIME_SECONDS || 600;
  SNYK_API_TOKEN = options.SNYK_API_TOKEN;
  ORG_NAME = options.ORG_NAME;
  BASE_URL = options.BASE_URL || 'https://snyk.io/api/v1';
  httpClient = axios.create({
    baseURL: BASE_URL,
    headers: {
      'Authorization': SNYK_API_TOKEN
    }
  });

}

async function backgroundWorker () {
  console.log('Background refresh starting...');

  try {
    var response = await getProjects(ORG_NAME);
    await processProjects(response.data);

    console.log('Background refresh completed.');
    up.set(1);
  } catch (err) {
    up.set(0);
    console.warn(error.message || error);
  }
  console.log(`Sleeping ${POLL_TIME_SECONDS} seconds`)

  setTimeout(backgroundWorker, POLL_TIME_SECONDS * 1000);
}

function startServer () {
  setTimeout(backgroundWorker, 1000);
  metricsServer.get('/metrics', async (req, res) => {
    res.contentType(prometheusClient.register.contentType);

    try {
      res.send(prometheusClient.register.metrics());
    } catch (error) {
      // error connecting
      up.set(0);
      res.header('X-Error', error.message || error);
      res.send(prometheusClient.register.getSingleMetricAsString(up.name));
    }
  });

  console.log('Server listening to 9207, metrics exposed on /metrics endpoint');
  metricsServer.listen(9207);
}

function shutdown () {
  metricsServer.close();
}

async function getProjects (orgName) {
  return httpClient.get(`/org/${orgName}/projects`);
}

async function processProjects (projectData) {
  let orgId;
  if (projectData.org && projectData.org.id) {
    orgId = projectData.org.id;
  } else {
    throw new Error('Unable to find org id in response data');
  }

  if (DEBUG) {
    console.log(`Retrieved ${projectData.projects.length} projects`);
  }

  for (let i = 0; i < projectData.projects.length; i++) {
    const project = projectData.projects[i];

    if (DEBUG) {
      console.log(`Project Name: ${project.name} Project ID: ${project.id}`);
    }

    let issueData = await getIssues(orgId, project);

    if (!issueData.data.issues) {
      throw new Error('Could not find issue object in response data');
    }

    let countsForProject = getVulnerabilityCounts(issueData.data.issues);

    let fullName = project.name.split(':');
    let projectName = (fullName.length) ? fullName[0] : 'unknown';
    let fileName = (fullName.length > 1) ? fullName[1] : 'unknown';

    setSeverityGauges(projectName, fileName, project.Id, countsForProject.severities);
    setTypeGauges(projectName, fileName, project.Id, countsForProject.types);
  }
}

async function getIssues (orgId, project) {
  if (!project) {
    throw new Error('project not provided');
  }

  const issuesQuery = `/org/${orgId}/project/${project.id}/issues`;

  return httpClient.post(
    issuesQuery,
    POST_DATA
  );
}

function getVulnerabilityCounts (issues) {
  const results = {
    severities: {
      high: 0,
      medium: 0,
      low: 0
    },
    types: {}
  };

  // dedupe vulnerabilities - the snyk API reports vulnerabilities as
  // separate if they are introduced via different top-level packages.
  // we remove duplicate occurrences by comparing the ID.
  const vulnerabilities = _.uniqWith(issues.vulnerabilities, (v1, v2) => {
    return v1.id === v2.id;
  });

  _.each(vulnerabilities, (thisVuln) => {
    const severity = thisVuln.severity;
    if (severity !== 'high' && severity !== 'medium' && severity !== 'low') {
      throw new Error('Invalid severity: ' + severity);
    }

    results.severities[severity]++;

    let thisType = thisVuln.title;
    if (!results.types[thisType]) {
      results.types[thisType] = 1;
    } else {
      results.types[thisType]++;
    }
  });

  return results;
}

function setSeverityGauges (projectName, fileName, projectId, severities) {
  _.each(severities, (count, severity) => {
    vulnerabilitiesBySeverity.set({
      project: projectName,
      path: fileName,
      severity: severity
    }, count);
  });
}

function setTypeGauges (projectName, fileName, projectId, types) {
  _.each(types, (count, type) => {
    // console.log(`Type: ${typeName}, Count: ${types[typeName]}`);
    vulnerabilitiesByType.set({
      project: projectName,
      path: fileName,
      type: type
    }, count);
  });
}

module.exports = {
  init: init,
  getProjects: getProjects,
  shutdown: shutdown
};

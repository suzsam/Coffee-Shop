/* ensure all variables on this page match your project
 */

export const environment = {
  production: false,
  apiServerUrl: 'http://127.0.0.1:5000', // the running FLASK api server url
  auth0: {
    url: 'fsnd-joel', // the auth0 domain prefix
    audience: 'coffee_api', // the audience set for the auth0 app --> same as "identifier"
    clientId: 'Q3OOJUkbDk1guLXFPqFMtmuZVqm9EAPq', // the client id generated for the auth0 app
    callbackURL: 'http://localhost:8100', // the base url of the running ionic application. 
  }
};

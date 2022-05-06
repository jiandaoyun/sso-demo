const fs = require('fs');
const express = require('express');
const samlify = require('samlify');

samlify.setSchemaValidator({
    validate: async () => 'skipped'
});

const config = {
    username: 'angelmsger'
};

const app = express();
app.set('views', __dirname);
app.set('view engine', 'ejs');

const sp = samlify.ServiceProvider({
    metadata: fs.readFileSync('./metadata-sp.xml')
});

const idp = samlify.IdentityProvider({
    metadata: fs.readFileSync('./metadata-idp.xml'),
    privateKey: fs.readFileSync('./key.pem'),
    loginResponseTemplate: Object.assign(
        Object.create(null),
        samlify.SamlLib.defaultLoginResponseTemplate, {
            attributes: [{
                name: 'username',
                nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
                valueXsiType: 'xs:string',
                valueTag: 'Username'
            }]
        }
    )
});

const renderSAML = (username, parseResult, acs) => {
    return (template) => {
        const id = idp.entitySetting.generateID();
        const acl = acs || sp.entityMeta.getAssertionConsumerService(
            samlify.Constants.namespace.binding.post
        );

        const bas = new Date();
        const iat = bas.toISOString();
        const off = new Date(bas.getTime());
        off.setMinutes(bas.getMinutes() + 5);
        const exp = off.toISOString();

        const values = {
            ID: id,
            AssertionID: idp.entitySetting.generateID(),
            Destination: acl,
            Audience: sp.entitySetting.entityID,
            EntityID: sp.entitySetting.entityID,
            SubjectRecipient: acl,
            Issuer: idp.entityMeta.getEntityID(),
            IssueInstant: iat,
            AssertionConsumerServiceURL: acl,
            StatusCode: samlify.Constants.StatusCode.Success,
            ConditionsNotBefore: iat,
            ConditionsNotOnOrAfter: exp,
            SubjectConfirmationDataNotOnOrAfter: exp,
            NameIDFormat: samlify.Constants.namespace.format[
                idp.entitySetting.logoutNameIDFormat
            ] || samlify.Constants.namespace.format.emailAddress,
            NameID: `${ username }@example.com`,
            InResponseTo: parseResult.extract.request.id,
            AuthnStatement: '',
            AttributeStatement: '',
            attrUsername: username
        };

        return {
            id,
            context: samlify.SamlLib.replaceTagsByValue(template, values)
        };
    };
};

// Cannot use async function in Prod with Express directly
app.get('/sso', async (req, res, next) => {
    const { query } = req;
    const { RelayState } = query;
    try {
        const parseResult = await idp.parseLoginRequest(sp, 'redirect', req);
        const { extract } = parseResult;
        const acs = extract.request.assertionConsumerServiceUrl;
        const { context } = await idp.createLoginResponse(
            sp, parseResult, 'post', {},
            renderSAML(config.username, parseResult, acs)
        );
        res.render('index', {
            acs,
            RelayState,
            SAMLResponse: context
        });
    } catch (e) {
        next(e);
    }
});

app.listen(8080);

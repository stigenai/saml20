import assert from 'assert';
import fs from 'fs';
import { createPublicKey } from 'crypto';
import * as xmlenc from 'xml-encryption';
import { parseFromString } from '../../lib/utils';
import { sign } from '../../lib/sign';
import { validate } from '../../lib/response';
import { validateBrowserProfile } from '../../lib/browserProfile';

const privateKey = fs.readFileSync('./test/assets/certificates/testIdpKey.pem', 'utf8');
const publicKey = fs.readFileSync('./test/assets/certificates/testIdpCert.crt', 'utf8');
const acs = 'https://sp.example.test/custom/acs';
const future = () => new Date(Date.now() + 3600_000).toISOString();
const bearer = (attrs = '', method = 'urn:oasis:names:tc:SAML:2.0:cm:bearer', prefix = 'saml') =>
  `<${prefix}:SubjectConfirmation Method="${method}"><${prefix}:SubjectConfirmationData ${attrs}/></${prefix}:SubjectConfirmation>`;
const good = () => bearer(`Recipient="${acs}" InResponseTo="request-1" NotOnOrAfter="${future()}"`);
const options = { publicKey, audience: 'audience', inResponseTo: 'request-1', expectedAcsUrl: acs };
function fixture(confirmations = good(), mode = 'assertion', destination = acs, responseID = 'request-1') {
  let xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:evil="urn:evil" ID="response" Version="2.0" Destination="${destination}" InResponseTo="${responseID}">
    <saml:Issuer>idp</saml:Issuer><saml:Assertion ID="assertion" Version="2.0"><saml:Issuer>idp</saml:Issuer>
    <saml:Subject><saml:NameID>user</saml:NameID>${confirmations}</saml:Subject>
    <saml:Conditions NotOnOrAfter="${future()}"><saml:AudienceRestriction><saml:Audience>audience</saml:Audience></saml:AudienceRestriction></saml:Conditions>
    </saml:Assertion></samlp:Response>`;
  if (mode === 'assertion' || mode === 'both')
    xml = sign(xml, privateKey, publicKey, '//*[local-name(.)="Assertion"]');
  if (mode === 'response' || mode === 'both')
    xml = sign(xml, privateKey, publicKey, '/*[local-name(.)="Response"]');
  return xml;
}

async function encryptedFixture(confirmations: string, responseSigned: boolean) {
  const xml = fixture(confirmations, responseSigned ? 'unsigned' : 'assertion');
  const doc = parseFromString(xml)!;
  const assertion = doc.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Assertion')[0];
  const encrypted = await new Promise<string>((resolve, reject) =>
    xmlenc.encrypt(
      assertion.toString(),
      {
        rsa_pub: createPublicKey(publicKey).export({ type: 'spki', format: 'pem' }),
        pem: publicKey,
        encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
        keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
      },
      (err, result) => (err ? reject(err) : resolve(result))
    )
  );
  const wrapper = doc.createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:EncryptedAssertion');
  wrapper.appendChild(doc.importNode(parseFromString(encrypted)!.documentElement!, true));
  doc.documentElement!.replaceChild(wrapper, assertion);
  return responseSigned
    ? sign(doc.toString(), privateKey, publicKey, '/*[local-name(.)="Response"]')
    : doc.toString();
}

describe('opt-in browser ACS binding', () => {
  for (const responseSigned of [false, true]) {
    it(`accepts encrypted assertions (response signed=${responseSigned})`, async () => {
      await validate(await encryptedFixture(good(), responseSigned), { ...options, privateKey });
    });
    it(`rejects encrypted wrong recipients (response signed=${responseSigned})`, async () => {
      await assert.rejects(
        validate(await encryptedFixture(good().replace(acs, 'https://other.test/acs'), responseSigned), {
          ...options,
          privateKey,
        })
      );
    });
  }
  for (const expectedAcsUrl of ['', null, false]) {
    it(`fails closed for invalid expected ACS ${JSON.stringify(expectedAcsUrl)}`, async () => {
      await assert.rejects(validate(fixture(), { ...options, expectedAcsUrl }));
    });
  }
  for (const mode of ['assertion', 'response', 'both']) {
    it(`accepts legitimate ${mode} signing`, async () => {
      assert.strictEqual((await validate(fixture(good(), mode), options)).issuer, 'idp');
    });
    it(`rejects a signed wrong recipient with ${mode} signing`, async () => {
      await assert.rejects(validate(fixture(good().replace(acs, 'https://other.test/acs'), mode), options));
    });
    it(`rejects wrong Destination with ${mode} signing`, async () => {
      await assert.rejects(validate(fixture(good(), mode, 'https://other.test/acs'), options));
    });
    it(`rejects contradictory Response correlation with ${mode} signing`, async () => {
      await assert.rejects(validate(fixture(good(), mode, acs, 'other-request'), options));
    });
    it(`accepts a later complete alternative with ${mode} signing`, async () => {
      await validate(fixture(good().replace('request-1', 'other-request') + good(), mode), options);
    });
  }
  for (const [name, confirmations] of [
    ['missing recipient', good().replace(`Recipient="${acs}"`, '')],
    ['missing correlation', good().replace('InResponseTo="request-1"', '')],
    ['missing bearer expiry', bearer(`Recipient="${acs}" InResponseTo="request-1"`)],
    [
      'NotBefore-only bearer',
      bearer(`Recipient="${acs}" InResponseTo="request-1" NotBefore="2000-01-01T00:00:00Z"`),
    ],
    ['invalid bearer expiry', good().replace(/NotOnOrAfter="[^"]+"/, 'NotOnOrAfter="invalid"')],
    ['expired bearer', good().replace(/NotOnOrAfter="[^"]+"/, 'NotOnOrAfter="2000-01-01T00:00:00Z"')],
    ['non-bearer method', good().replace('cm:bearer', 'cm:holder-of-key')],
    ['foreign namespace', good().replaceAll('saml:', 'evil:')],
    [
      'split correlation and recipient',
      good().replace('request-1', 'other-request') + good().replace(acs, 'https://other.test/acs'),
    ],
    [
      'split validity and recipient',
      good().replace(/NotOnOrAfter="[^"]+"/, 'NotOnOrAfter="2000-01-01T00:00:00Z"') +
        good().replace(acs, 'https://other.test/acs'),
    ],
    [
      'duplicate data in one confirmation',
      good().replace(
        '</saml:SubjectConfirmation>',
        good().match(/<saml:SubjectConfirmationData[^>]*\/>/)![0] + '</saml:SubjectConfirmation>'
      ),
    ],
  ]) {
    it(`rejects ${name}`, async () => {
      await assert.rejects(validate(fixture(confirmations), options));
    });
  }
  it('does not change callers without the option', async () => {
    const legacy = { publicKey, audience: options.audience, inResponseTo: options.inResponseTo };
    await validate(fixture(good().replace(acs, 'https://other.test/acs')), legacy);
  });
  it('checks the verified Response independently of original envelope correlation', () => {
    assert.throws(
      () =>
        validateBrowserProfile(
          fixture(good(), 'unsigned', acs, 'wrong-request'),
          fixture(),
          acs,
          'request-1'
        ),
      /Invalid InResponseTo/
    );
  });
  it('permits an absent unsigned Destination and Response correlation', async () => {
    const xml = fixture().replace(` Destination="${acs}"`, '').replace(' InResponseTo="request-1"', '');
    await validate(xml, options);
  });
  it('does not bypass the strict bearer window with bypassExpiration', async () => {
    await assert.rejects(
      validate(fixture(good().replace(/NotOnOrAfter="[^"]+"/, 'NotOnOrAfter="2000-01-01T00:00:00Z"')), {
        ...options,
        bypassExpiration: true,
      })
    );
  });
});

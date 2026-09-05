import assert from 'assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { execFileSync } from 'child_process';
import { parse, validate } from '../../lib/response';
import { sign } from '../../lib/sign';

// The legacy Okta fixture has malformed UTCTime under current OpenSSL. Generate
// disposable test-only material rather than bypassing certificate validation.
const certificateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'saml-nameid-proof-'));
let privateKey: string;
let publicKey: string;
try {
  execFileSync(
    'openssl',
    [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-days',
      '1',
      '-subj',
      '/CN=saml-nameid-proof.invalid',
      '-keyout',
      path.join(certificateDir, 'key.pem'),
      '-out',
      path.join(certificateDir, 'cert.pem'),
    ],
    { stdio: 'ignore' }
  );
  privateKey = fs.readFileSync(path.join(certificateDir, 'key.pem'), 'utf8');
  publicKey = fs.readFileSync(path.join(certificateDir, 'cert.pem'), 'utf8');
} finally {
  fs.rmSync(certificateDir, { recursive: true, force: true });
}
const persistent = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
const transient = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';
const opts = { publicKey, audience: 'https://sp.example.test', inResponseTo: 'request-1' };

function fixture(nameID: string, responseSigned = false) {
  const now = new Date().toISOString();
  const expires = new Date(Date.now() + 60000).toISOString();
  const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response" Version="2.0"
    IssueInstant="${now}" InResponseTo="request-1">
    <saml:Issuer>https://idp.example.test</saml:Issuer>
    <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
    <saml:Assertion ID="_assertion" Version="2.0" IssueInstant="${now}">
      <saml:Issuer>https://idp.example.test</saml:Issuer>
      <saml:Subject>${nameID}<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="request-1" NotOnOrAfter="${expires}"/>
      </saml:SubjectConfirmation></saml:Subject>
      <saml:Conditions NotOnOrAfter="${expires}"><saml:AudienceRestriction>
        <saml:Audience>https://sp.example.test</saml:Audience>
      </saml:AudienceRestriction></saml:Conditions>
      <saml:AttributeStatement><saml:Attribute Name="verifiedSubjectNameID">
        <saml:AttributeValue>attacker-controlled-claim</saml:AttributeValue>
      </saml:Attribute></saml:AttributeStatement>
    </saml:Assertion>
  </samlp:Response>`;
  return sign(
    xml,
    privateKey,
    publicKey,
    responseSigned ? '/*[local-name(.)="Response"]' : '//*[local-name(.)="Assertion"]'
  );
}

describe('signature-validated Subject NameID provenance', () => {
  for (const responseSigned of [false, true]) {
    it(`exposes exact value and format only after validation (response signed=${responseSigned})`, async () => {
      const xml = fixture(`<saml:NameID Format="${persistent}"> user  1 </saml:NameID>`, responseSigned);
      const untrusted = await parse(xml);
      assert.strictEqual(untrusted.verifiedSubjectNameID, undefined);
      const trusted = await validate(xml, opts);
      assert.deepStrictEqual(trusted.verifiedSubjectNameID, { value: ' user  1 ', format: persistent });
      assert.strictEqual(trusted.claims.verifiedSubjectNameID, 'attacker-controlled-claim');
    });
  }
  it('preserves distinct NameID formats', async () => {
    const a = await validate(fixture(`<saml:NameID Format="${persistent}">user</saml:NameID>`), opts);
    const b = await validate(fixture(`<saml:NameID Format="${transient}">user</saml:NameID>`), opts);
    assert.notDeepStrictEqual(a.verifiedSubjectNameID, b.verifiedSubjectNameID);
  });
  for (const nameID of [
    '',
    '<saml:NameID>user</saml:NameID>',
    '<saml:NameID Format="">user</saml:NameID>',
    `<saml:NameID Format="${persistent}"></saml:NameID>`,
    `<saml:NameID Format="${persistent}">one</saml:NameID><saml:NameID Format="${persistent}">two</saml:NameID>`,
  ]) {
    it(`does not attest missing or ambiguous NameID: ${nameID}`, async () => {
      const profile = await validate(fixture(nameID), opts);
      assert.strictEqual(profile.verifiedSubjectNameID, undefined);
    });
  }
  it('rejects post-signature NameID modification', async () => {
    const xml = fixture(`<saml:NameID Format="${persistent}">original</saml:NameID>`);
    await assert.rejects(validate(xml.replace('>original<', '>tampered<'), opts));
  });
  it('ignores a NameID injected into the unsigned Response wrapper', async () => {
    const xml = fixture(`<saml:NameID Format="${persistent}">original</saml:NameID>`);
    const wrapped = xml.replace(
      '<saml:Assertion',
      `<saml:Subject><saml:NameID Format="${transient}">attacker</saml:NameID></saml:Subject><saml:Assertion`
    );
    const profile = await validate(wrapped, opts);
    assert.deepStrictEqual(profile.verifiedSubjectNameID, { value: 'original', format: persistent });
  });
});

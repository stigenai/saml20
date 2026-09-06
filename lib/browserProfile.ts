import { Element } from '@xmldom/xmldom';
import { parseFromString } from './utils';
import { checkWindow } from './saml20';

const assertionNS = 'urn:oasis:names:tc:SAML:2.0:assertion';
const protocolNS = 'urn:oasis:names:tc:SAML:2.0:protocol';
const children = (parent: Element, name: string): Element[] =>
  Array.from(parent.childNodes)
    .filter((node) => node.nodeType === 1)
    .map((node) => node as Element)
    .filter((node) => node.namespaceURI === assertionNS && node.localName === name);

// Only verifiedXML can establish bearer authority. The original envelope is
// checked for contradictions, never used to supply missing signed attributes.
export function validateBrowserProfile(
  verifiedXML: string,
  responseXML: string,
  expectedAcsUrl: string,
  inResponseTo?: string
): void {
  if (typeof expectedAcsUrl !== 'string' || !expectedAcsUrl) {
    throw new Error('Invalid expected ACS URL.');
  }
  const envelope = parseFromString(responseXML)?.documentElement;
  if (!envelope || envelope.namespaceURI !== protocolNS || envelope.localName !== 'Response') {
    throw new Error('Invalid SAML Response envelope.');
  }
  if (envelope.hasAttribute('Destination') && envelope.getAttribute('Destination') !== expectedAcsUrl) {
    throw new Error('Invalid Destination.');
  }
  if (
    inResponseTo &&
    envelope.hasAttribute('InResponseTo') &&
    envelope.getAttribute('InResponseTo') !== inResponseTo
  ) {
    throw new Error('Invalid InResponseTo.');
  }
  const root = parseFromString(verifiedXML)?.documentElement;
  if (!root) throw new Error('Invalid signed browser assertion.');
  if (root.namespaceURI === protocolNS && root.localName === 'Response') {
    if (root.hasAttribute('Destination') && root.getAttribute('Destination') !== expectedAcsUrl) {
      throw new Error('Invalid Destination.');
    }
    if (
      inResponseTo &&
      root.hasAttribute('InResponseTo') &&
      root.getAttribute('InResponseTo') !== inResponseTo
    ) {
      throw new Error('Invalid InResponseTo.');
    }
  }
  const assertions =
    root.namespaceURI === assertionNS && root.localName === 'Assertion'
      ? [root]
      : root.namespaceURI === protocolNS && root.localName === 'Response'
        ? children(root, 'Assertion')
        : [];
  if (assertions.length !== 1) throw new Error('Invalid signed browser assertion.');
  const subjects = children(assertions[0], 'Subject');
  if (subjects.length !== 1) throw new Error('Invalid bearer SubjectConfirmation.');
  const valid = children(subjects[0], 'SubjectConfirmation').some((confirmation) => {
    if (confirmation.getAttribute('Method') !== 'urn:oasis:names:tc:SAML:2.0:cm:bearer') return false;
    const data = children(confirmation, 'SubjectConfirmationData');
    if (data.length !== 1) return false;
    const tuple = data[0];
    return (
      tuple.getAttribute('Recipient') === expectedAcsUrl &&
      (!inResponseTo || tuple.getAttribute('InResponseTo') === inResponseTo) &&
      checkWindow(
        tuple.getAttribute('NotBefore') || undefined,
        tuple.getAttribute('NotOnOrAfter') || undefined
      ) === 'valid'
    );
  });
  if (!valid) throw new Error('Invalid bearer SubjectConfirmation.');
}

import type * as dns from 'dns';
declare let osDns: dns & { withNodeFallback: dns };
export = osDns;

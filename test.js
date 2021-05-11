'use strict';
const assert = require('assert');
const nodeDns = require('dns');
const osDns = require('./');

describe('lookup', function() {
  this.timeout(60_000);
  const queries = [
    { type: 'A', method: 'resolve4', hostname: 'example.org' },
    { type: 'AAAA', method: 'resolve6', hostname: 'example.org' },
    { type: 'TXT', method: 'resolveTxt', hostname: 'example.org' },
    { type: 'CNAME', method: 'resolveCname', hostname: 'en.wikipedia.org' },
    { type: 'SRV', method: 'resolveSrv', hostname: '_mongodb._tcp.cluster0.ucdwm.mongodb.net' },
  ];

  for (const useOsDns of [osDns, osDns.withNodeFallback]) {
    context(`when ${useOsDns === osDns ? 'not ': ''}using a Node.js fallback`, () => {
      for (const { type, method, hostname } of queries) {
        context(`for a ${type} query`, () => {
          it('looks up with resolve() and matches Node.js', (done) => {
            osDns.resolve(hostname, type, ((err, osResults) => {
              if (err) { return done(err); }
              nodeDns.resolve(hostname, type, ((err, nodeResults) => {
                if (err) { return done(err); }
                assert.deepStrictEqual(new Set(osResults), new Set(nodeResults));
                done();
              }));
            }));
          });

          it('looks up with resolve<X>() and matches Node.js', (done) => {
            osDns[method](hostname, ((err, osResults) => {
              if (err) { return done(err); }
              nodeDns[method](hostname, ((err, nodeResults) => {
                if (err) { return done(err); }
                assert.deepStrictEqual(new Set(osResults), new Set(nodeResults));
                done();
              }));
            }));
          });

          it('looks up with promises.resolve() and matches Node.js', async() => {
            const [ osResults, nodeResults ] = await Promise.all([
              osDns.promises.resolve(hostname, type),
              nodeDns.promises.resolve(hostname, type),
            ]);
            assert.deepStrictEqual(new Set(osResults), new Set(nodeResults));
          });

          it('looks up with promises.resolve<X>() and matches Node.js', async() => {
            const [ osResults, nodeResults ] = await Promise.all([
              osDns.promises[method](hostname),
              nodeDns.promises[method](hostname),
            ]);
            assert.deepStrictEqual(new Set(osResults), new Set(nodeResults));
          });
        });
      }

      for (const { type, method } of queries) {
        it('provides an error with resolve()', (done) => {
          osDns.resolve('nonexistent.nx', type, (err) => {
            if (!err) {
              return done(new Error('missed exception'));
            }
            done();
          });
        });

        it('provides an error with resolve<X>()', (done) => {
          osDns[method]('nonexistent.nx', (err) => {
            if (!err) {
              return done(new Error('missed exception'));
            }
            done();
          });
        });

        it('provides an error with promises.resolve()', async() => {
          await assert.rejects(() => osDns.promises.resolve('nonexistent.nx', type));
        });

        it('provides an error with promises.resolve<X>()', async() => {
          await assert.rejects(() => osDns.promises[method]('nonexistent.nx'));
        });
      }
    });
  }
});

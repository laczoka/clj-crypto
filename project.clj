(defproject laczoka/clj-crypto "1.1"
  :description "Clj-crypto is a wrapper for Bouncy Castle which allows you to easily use cryptography in your clojure app."
  :global-vars {*warn-on-reflection* true}
  :dependencies [[org.bouncycastle/bcprov-jdk15on "1.50"]
                 [commons-codec/commons-codec "1.5"]
                 [org.clojure/clojure "1.6.0"]])

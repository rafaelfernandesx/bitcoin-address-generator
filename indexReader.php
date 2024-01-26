<?php
class IndexedReader {
    private $index;
    private $filename;

    public function __construct($filename) {
        $this->filename = $filename;
        $this->buildIndex();
    }

    private function buildIndex() {
        $this->index = [];
        $handle = fopen($this->filename, "r");
        if ($handle) {
            while (($line = fgets($handle)) !== false) {
                $address = str_replace(["\r", "\n"], '', $line);
                $this->index[$address] = true;
            }
            fclose($handle);
        }
    }

    public function findValueByName($name) {
        return isset($this->index[$name]);
    }
}
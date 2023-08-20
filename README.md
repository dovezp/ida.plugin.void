# Void - A 'No Operation' Generator Plugin

Welcome to the Void Plugin repository for [IDA Pro](https://www.hex-rays.com/products/ida/)! If you're a reverse engineer, security analyst, or software enthusiast who often works with IDA Pro, you're about to discover a handy tool that simplifies the process of generating 'no operation' (NOP) sequences.

### Repository Status Update
Regarding the current status of the IDA Plugin Void repository. As you may have noticed, there have been no updates or developments since September 2020. It's noteworthy that while the plugin's most recent refactor for IDA 7.5 remains compatible with IDA 7.6 and 7.7, I must address an important consideration: no further updates have been undertaken to ensure future support due to the unavailability of licensing resources. In light of this prolonged inactivity, I have made the decision to archive the IDA Plugin Void repository.

### Highlights
* Streamlined NOP Generation: Void Plugin provides a set of intuitive right-click actions that allow you to effortlessly create NOP'd areas in your disassembly view.

* Enhanced Customization: By offering convenient right-click options for various objects, including instructions, data, functions, and more, the plugin puts the power of NOP generation at your fingertips.

* Version Compatibility: Void Plugin is designed for IDA Pro versions [7.0](https://github.com/dovezp/ida.plugin.void/tree/7.0) and [7.5](https://github.com/dovezp/ida.plugin.void/tree/7.5), ensuring it caters to a wide range of users.

### Feature Demo
Witness the simplicity and efficiency of the Void Plugin in action:

![Void in Action](https://i.imgur.com/vgsHJXw.png)

### Installation

Integrating Void into your IDA Pro environment is straightforward:

1. Download the latest branch for either IDA Pro versions [7.0](https://github.com/dovezp/ida.plugin.void/tree/7.0), or [7.5](https://github.com/dovezp/ida.plugin.void/tree/7.5).
2. Identify your IDA's plugin directory by running the following command in IDA's Python console:
  * **IDA Pro**: `os.path.join(idaapi.get_user_idadir(), "plugins")`

3. Copy the contents of this repository's `/plugin/` folder into the designated directory.
4. Restart IDA Pro.

### Usage

The Void Plugin enhances your workflow with a set of context-specific actions in both the Disassembly and Functions views. Here are some key actions you can perform:

### Disassembly Window

#### NOP Current Selection

Right clicking a selected region in the disassembly view now provides an option to 'nop' the entire selection.

An alternative usage is the hotkey (shift+s).

#### NOP Current Instruction

Right clicking a instruction object in the disassembly view now provides an option to 'nop' instruction.

An alternative usage is the hotkey (shift+i).

#### NOP Current Unknown

Right clicking a unknown object in the disassembly view now provides an option to create a 'nop' instruction.

An alternative usage is the hotkey (shift+u).

#### NOP Current Data

Right clicking a data object in the disassembly view now provides an option to 'nop' the data.

An alternative usage is the hotkey (shift+d).

#### ZERO Current Data

Right clicking a data object in the disassembly view now provides an option to 'zero' the data.

An alternative usage is the hotkey (shift+z).

#### ZERO Current ASCII

Right clicking a ascii string object in the disassembly view now provides an option to 'zero' the ascii string.

An alternative usage is the hotkey (shift+a).

#### NOP Current Function

Right clicking a function in the disassembly view now provides an option to 'nop' the entire function.

An alternative usage is the hotkey (shift+f).

#### NOP Current Function Block

Right clicking a function block in the disassembly view now provides an option to 'nop' the block function.

An alternative usage is the hotkey (shift+b).

### Functions Window

### NOP Selected Function(s)

Right clicking one or more functions in the function view now provides an option to 'nop' function(s).

An alternative usage is the hotkey (shift+f).

### License

This project operates under the [BSD 3-Clause License (Revised)](https://tldrlegal.com/license/bsd-3-clause-license-(revised)) reflecting a commitment to open collaboration.

### Your Feedback Counts

Your insights and feedback, whether positive or constructive, are immensely valuable. Your contributions guide the refinement of the Void Plugin for future iterations.

Share your thoughts by opening an issue in the [repository's issue section](https://github.com/dovezp/ida.plugin.void/issues). Be sure to provide context and links when sharing your feedback.

Thank you for being an essential part of the Void Plugin's growth journey.

<p align="center">
  <p align="center">
    <a href="https://hits.seeyoufarm.com/api/count/graph/dailyhits.svg?url=https://github.com/dovezp/ida.plugin.void">
      <img src="https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2Fdovezp%2Fida.plugin.void&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=hits&edge_flat=true" alt="repository hits">
    </a>
    <a href="https://github.com/dovezp/ida.plugin.void/releases">
      <img src="https://img.shields.io/github/downloads/dovezp/ida.plugin.void/total?style=flat-square" alt="downloads"/>
    </a>
    <a href="https://github.com/dovezp/ida.plugin.void/graphs/contributors">
      <img src="https://img.shields.io/github/contributors/dovezp/ida.plugin.void?style=flat-square" alt="contributors"/>
    </a>
    <a href="https://github.com/dovezp/ida.plugin.void/watchers">
      <img src="https://img.shields.io/github/watchers/dovezp/ida.plugin.void?style=flat-square" alt="watchers"/>
    </a>
    <a href="https://github.com/dovezp/ida.plugin.void/stargazers">
      <img src="https://img.shields.io/github/stars/dovezp/ida.plugin.void?style=flat-square" alt="stars"/>
    </a>
    <a href="https://github.com/dovezp/ida.plugin.void/network/members">
      <img src="https://img.shields.io/github/forks/dovezp/ida.plugin.void?style=flat-square" alt="forks"/>
    </a>
  </p>
</p>

<p align="center">
  <a href="https://github.com/dovezp">
    <img width="64" heigth="64" src="https://avatars.githubusercontent.com/u/89095890" alt="dovezp"/>
  </a>
</p>
